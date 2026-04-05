# --- START OF FILE dfu_lib.py ---
import asyncio
import logging
import struct
import zipfile
import json
import os
import warnings
from typing import Optional, Callable, List

from bleak import BleakScanner, BleakClient, BleakError
from bleak.backends.device import BLEDevice

# --- UUID Constants ---
# Legacy DFU (SDK 4.3 - 11)
DFU_SERVICE_UUID = "00001530-1212-efde-1523-785feabcd123"
DFU_CONTROL_POINT_UUID = "00001531-1212-efde-1523-785feabcd123"
DFU_PACKET_UUID = "00001532-1212-efde-1523-785feabcd123"
DFU_VERSION_UUID = "00001534-1212-efde-1523-785feabcd123"

# Secure DFU (SDK 12+)
SECURE_DFU_SERVICE_UUID = "0000fe59-0000-1000-8000-00805f9b34fb"
SECURE_DFU_CONTROL_POINT_UUID = "8ec90001-f315-4f60-9fb8-838830daea50"
SECURE_DFU_PACKET_UUID = "8ec90002-f315-4f60-9fb8-838830daea50"

# Buttonless DFU characteristics (for jumping from app mode to bootloader)
BUTTONLESS_WITHOUT_BONDS_UUID = "8ec90003-f315-4f60-9fb8-838830daea50"
BUTTONLESS_WITH_BONDS_UUID = "8ec90004-f315-4f60-9fb8-838830daea50"
BUTTONLESS_EXPERIMENTAL_UUID = "8e400001-f315-4f60-9fb8-838830daea50"

# --- Op Codes ---
OP_CODE_START_DFU = 0x01
OP_CODE_INIT_DFU_PARAMS = 0x02
OP_CODE_RECEIVE_FIRMWARE_IMAGE = 0x03
OP_CODE_VALIDATE = 0x04
OP_CODE_ACTIVATE_AND_RESET = 0x05
OP_CODE_RESET = 0x06
OP_CODE_PACKET_RECEIPT_NOTIF_REQ = 0x08
OP_CODE_RESPONSE_CODE = 0x10
OP_CODE_PACKET_RECEIPT_NOTIF = 0x11
OP_CODE_ENTER_BOOTLOADER = 0x01
SECURE_DFU_RESPONSE_CODE = 0x20
UPLOAD_MODE_SOFTDEVICE  = 0x01
UPLOAD_MODE_BOOTLOADER  = 0x02
UPLOAD_MODE_SD_BL       = 0x03  # SoftDevice + Bootloader combined
UPLOAD_MODE_APPLICATION = 0x04

_UPLOAD_MODE_NAMES = {
    UPLOAD_MODE_SOFTDEVICE:  "SoftDevice",
    UPLOAD_MODE_BOOTLOADER:  "Bootloader",
    UPLOAD_MODE_SD_BL:       "SoftDevice+Bootloader",
    UPLOAD_MODE_APPLICATION: "Application",
}

logger = logging.getLogger("DFU_LIB")

class DfuException(Exception):
    pass

class NordicLegacyDFU:
    def __init__(self, zip_path: str, prn: int, packet_delay: float, adapter: str = None,
                 high_mtu: bool = False,
                 progress_callback: Callable[[int], None] = None,
                 log_callback: Callable[[str], None] = None):
        self.zip_path = zip_path
        self.prn = prn
        self.packet_delay = packet_delay
        self.adapter = adapter
        self.high_mtu = high_mtu
        self.progress_callback = progress_callback
        self.log_callback = log_callback

        self.manifest = None
        self.bin_data = None
        self.dat_data = None
        self.upload_mode = UPLOAD_MODE_APPLICATION
        self.sd_size = 0
        self.bl_size = 0
        self.app_size = 0
        self.client: Optional[BleakClient] = None

        self.response_queue = asyncio.Queue()
        self.pkg_receipt_event = asyncio.Event()
        self.bytes_sent = 0
        self.reset_in_progress = False

    def _log(self, msg: str, level=logging.INFO):
        """Internal helper to route logs to both logger and callback."""
        if level == logging.ERROR:
            logger.error(msg)
        elif level == logging.DEBUG:
            logger.debug(msg)
        else:
            logger.info(msg)

        if self.log_callback:
            self.log_callback(msg)

    async def _setup_mtu(self):
        if not self.client:
            return 23

        if not self.high_mtu:
            return 23

        if hasattr(self.client, "_backend"):
            if hasattr(self.client._backend, "_acquire_mtu"):
                try:
                    await self.client._backend._acquire_mtu()
                except Exception:
                    pass

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            try:
                mtu = self.client.mtu_size
            except:
                mtu = 23
        return mtu

    def parse_zip(self):
        if not os.path.exists(self.zip_path):
            raise FileNotFoundError(f"File not found: {self.zip_path}")

        with zipfile.ZipFile(self.zip_path, 'r') as z:
            if 'manifest.json' in z.namelist():
                with z.open('manifest.json') as f:
                    self.manifest = json.load(f)

                m = self.manifest.get('manifest', {})

                if 'softdevice_bootloader' in m:
                    info = m['softdevice_bootloader']
                    self.bin_data = z.read(info['bin_file'])
                    self.dat_data = z.read(info['dat_file'])
                    self.sd_size = info.get('sd_size', 0)
                    self.bl_size = info.get('bl_size', 0)
                    if self.sd_size == 0 and self.bl_size == 0:
                        raise DfuException(
                            "softdevice_bootloader manifest entry must include 'sd_size' and 'bl_size'.")
                    self.app_size = 0
                    self.upload_mode = UPLOAD_MODE_SD_BL

                elif 'bootloader' in m:
                    info = m['bootloader']
                    self.bin_data = z.read(info['bin_file'])
                    self.dat_data = z.read(info['dat_file'])
                    self.sd_size = 0
                    self.bl_size = len(self.bin_data)
                    self.app_size = 0
                    self.upload_mode = UPLOAD_MODE_BOOTLOADER

                elif 'softdevice' in m:
                    info = m['softdevice']
                    self.bin_data = z.read(info['bin_file'])
                    self.dat_data = z.read(info['dat_file'])
                    self.sd_size = len(self.bin_data)
                    self.bl_size = 0
                    self.app_size = 0
                    self.upload_mode = UPLOAD_MODE_SOFTDEVICE

                elif 'application' in m:
                    info = m['application']
                    self.bin_data = z.read(info['bin_file'])
                    self.dat_data = z.read(info['dat_file'])
                    self.sd_size = 0
                    self.bl_size = 0
                    self.app_size = len(self.bin_data)
                    self.upload_mode = UPLOAD_MODE_APPLICATION

                else:
                    raise DfuException(
                        "Unrecognized manifest. Expected one of: application, bootloader, "
                        "softdevice, or softdevice_bootloader.")

            else:
                self._log("No manifest.json. Attempting legacy compatibility mode.")
                files = z.namelist()

                bl_bin  = next((f for f in files if f.endswith('.bin') and 'bootloader'  in f.lower()), None)
                sd_bin  = next((f for f in files if f.endswith('.bin') and 'softdevice'  in f.lower()), None)
                app_bin = next((f for f in files if f.endswith('.bin') and 'application' in f.lower()), None)
                bl_dat  = next((f for f in files if f.endswith('.dat') and 'bootloader'  in f.lower()), None)
                sd_dat  = next((f for f in files if f.endswith('.dat') and 'softdevice'  in f.lower()), None)
                app_dat = next((f for f in files if f.endswith('.dat') and 'application' in f.lower()), None)

                if bl_bin and sd_bin:
                    raise DfuException(
                        "Found both softdevice and bootloader BINs without a manifest.json. "
                        "Cannot determine individual sizes. Please add a manifest.json with "
                        "'sd_size' and 'bl_size'.")
                elif bl_bin:
                    self.bin_data = z.read(bl_bin)
                    self.dat_data = z.read(bl_dat) if bl_dat else b''
                    self.sd_size = 0
                    self.bl_size = len(self.bin_data)
                    self.app_size = 0
                    self.upload_mode = UPLOAD_MODE_BOOTLOADER
                elif sd_bin:
                    self.bin_data = z.read(sd_bin)
                    self.dat_data = z.read(sd_dat) if sd_dat else b''
                    self.sd_size = len(self.bin_data)
                    self.bl_size = 0
                    self.app_size = 0
                    self.upload_mode = UPLOAD_MODE_SOFTDEVICE
                elif app_bin and app_dat:
                    self.bin_data = z.read(app_bin)
                    self.dat_data = z.read(app_dat)
                    self.sd_size = 0
                    self.bl_size = 0
                    self.app_size = len(self.bin_data)
                    self.upload_mode = UPLOAD_MODE_APPLICATION
                else:
                    raise DfuException("Could not auto-detect firmware files in ZIP.")

    async def _notification_handler(self, sender, data):
        data = bytearray(data)
        opcode = data[0]

        if opcode == OP_CODE_RESPONSE_CODE:
            request_op = data[1]
            status = data[2]
            logger.debug(f"<< RX Resp: Op={request_op:#02x} Status={status}")
            await self.response_queue.put((request_op, status))

        elif opcode == SECURE_DFU_RESPONSE_CODE:
            request_op = data[1]
            status = data[2]
            logger.debug(f"<< RX Secure Resp: Op={request_op:#02x} Status={status}")
            await self.response_queue.put((request_op, status))

        elif opcode == OP_CODE_PACKET_RECEIPT_NOTIF:
            if len(data) >= 5:
                bytes_received = struct.unpack('<I', data[1:5])[0]
                logger.debug(f"<< RX PRN: {bytes_received}")
            self.pkg_receipt_event.set()

    async def _wait_for_response(self, expected_op_code, timeout=30.0):
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                self._log(f"Timeout ({timeout}s) waiting for response to op={expected_op_code:#02x}", logging.ERROR)
                return -1
            try:
                request_op, status = await asyncio.wait_for(self.response_queue.get(), remaining)
                if request_op != expected_op_code:
                    logger.debug(f"Discarding stale response op={request_op:#02x}, waiting for {expected_op_code:#02x}")
                    continue
                if status != 1:  # 1 = SUCCESS
                    self._log(f"<< RX Error: Command {expected_op_code:#02x} failed with status {status}", logging.ERROR)
                    return status
                return 1
            except asyncio.TimeoutError:
                self._log(f"Timeout ({timeout}s) waiting for response to op={expected_op_code:#02x}", logging.ERROR)
                return -1

    async def _clear_ble_cache(self, address: str):
        """Clear BlueZ GATT cache for a device (Linux only). Equivalent to Android's refreshDeviceCache()."""
        import platform
        if platform.system() != "Linux":
            return
        try:
            import subprocess
            # Remove the device from BlueZ to clear its cached services
            result = subprocess.run(
                ["bluetoothctl", "remove", address],
                timeout=5, capture_output=True, text=True
            )
            logger.debug(f"bluetoothctl remove {address}: {result.stdout.strip()} {result.stderr.strip()}")
            await asyncio.sleep(0.5)
        except Exception as e:
            logger.debug(f"Cache clear failed (non-fatal): {e}")

    async def _connect_with_retry(self, device, max_retries=3, clear_cache=False):
        """Connect to a device with retries, handling BlueZ cache issues on Linux."""
        if clear_cache:
            await self._clear_ble_cache(device.address)

        for attempt in range(max_retries):
            try:
                client = BleakClient(device, timeout=30.0, adapter=self.adapter)
                await client.connect()
                # Verify services were discovered
                if not client.services or len(list(client.services)) == 0:
                    try:
                        await client.disconnect()
                    except Exception:
                        pass
                    raise BleakError("No services discovered")
                return client
            except Exception as e:
                self._log(f"Connection attempt {attempt+1}/{max_retries} failed: {e}", logging.WARNING)
                try:
                    await client.disconnect()
                except Exception:
                    pass
                if attempt < max_retries - 1:
                    # Clear cache before retrying — stale GATT data is the most common cause
                    await self._clear_ble_cache(device.address)
                    await asyncio.sleep(2.0)
                else:
                    raise

    async def jump_to_bootloader(self, device: BLEDevice):
        self._log(f"Connecting to {device.name} ({device.address}) for Jump...")
        write_attempted = False
        try:
            client = await self._connect_with_retry(device)
            self._log("Connected. Services discovered.")

            services = client.services
            char_uuids = [c.uuid.lower() for s in services for c in s.characteristics]

            logger.debug(f"Characteristics: {char_uuids}")

            jump_char = None
            jump_payload = None
            jump_type = None
            use_indications = False

            # Detection order matches Android DFU library:
            # 1. Secure DFU Buttonless with Bond Sharing (SDK 14+) — uses indications
            if BUTTONLESS_WITH_BONDS_UUID.lower() in char_uuids:
                jump_char = BUTTONLESS_WITH_BONDS_UUID
                jump_payload = bytearray([0x01])
                jump_type = "Secure Buttonless (with bonds, SDK 14+)"
                use_indications = True
            # 2. Secure DFU Buttonless without Bond Sharing (SDK 13) — uses indications
            elif BUTTONLESS_WITHOUT_BONDS_UUID.lower() in char_uuids:
                jump_char = BUTTONLESS_WITHOUT_BONDS_UUID
                jump_payload = bytearray([0x01])
                jump_type = "Secure Buttonless (no bonds, SDK 13+)"
                use_indications = True
            # 3. Legacy DFU Buttonless (SDK 6.1-11) — uses notifications
            elif DFU_CONTROL_POINT_UUID.lower() in char_uuids:
                jump_char = DFU_CONTROL_POINT_UUID
                jump_payload = bytearray([OP_CODE_ENTER_BOOTLOADER, UPLOAD_MODE_APPLICATION])
                jump_type = "Legacy Buttonless (SDK 6.1-11)"
            # 4. Experimental Buttonless (SDK 12.x) — uses notifications
            elif BUTTONLESS_EXPERIMENTAL_UUID.lower() in char_uuids:
                jump_char = BUTTONLESS_EXPERIMENTAL_UUID
                jump_payload = bytearray([0x01])
                jump_type = "Experimental Buttonless (SDK 12.x)"

            if not jump_char:
                self._log("No buttonless DFU characteristic found. Device may already be in bootloader mode.", logging.WARNING)
                try:
                    await client.disconnect()
                except Exception:
                    pass
                return

            self._log(f"Detected: {jump_type}")

            # Clear stale responses
            while not self.response_queue.empty():
                self.response_queue.get_nowait()

            # Step 1: Enable CCCD — exactly as Android does it.
            # Android does: gatt.setCharacteristicNotification() + explicit descriptor write to 0x2902
            # For indications: write [0x02, 0x00], for notifications: write [0x01, 0x00]
            # Bleak's start_notify should handle this, but we also manually write the CCCD
            # descriptor to ensure it's correct (especially indications vs notifications).
            CCCD_UUID = "00002902-0000-1000-8000-00805f9b34fb"
            cccd_value = bytearray([0x02, 0x00]) if use_indications else bytearray([0x01, 0x00])

            try:
                await client.start_notify(jump_char, self._notification_handler)
                self._log(f"Enabled {'indications' if use_indications else 'notifications'} on jump characteristic.")
            except Exception as e:
                # Fallback: manually write the CCCD descriptor
                self._log(f"start_notify failed ({e}), trying manual CCCD write...", logging.WARNING)
                try:
                    # Find the characteristic and its CCCD descriptor
                    for s in services:
                        for c in s.characteristics:
                            if c.uuid.lower() == jump_char.lower():
                                for d in c.descriptors:
                                    if d.uuid.lower() == CCCD_UUID:
                                        await client.write_gatt_descriptor(d.handle, cccd_value)
                                        self._log("CCCD descriptor written manually.")
                                        break
                except Exception as e2:
                    self._log(f"Manual CCCD write also failed: {e2}", logging.WARNING)

            # Step 2: Write the jump command (write-with-response, same as Android)
            self._log(f"Writing jump command to {jump_char}...")
            logger.debug(f">> TX Jump: {jump_payload.hex()}")
            write_attempted = True
            try:
                await client.write_gatt_char(jump_char, jump_payload, response=True)
                self._log("Jump write acknowledged by device.")
            except Exception as e:
                logger.debug(f"Write exception (may be expected if device rebooted): {e}")

            # Step 3: Wait for notification/indication response — Android does this!
            # Response format: [0x20, 0x01, 0x01] for secure, [0x10, 0x01, 0x01] for legacy
            # The device confirms it accepted the jump command before rebooting.
            # On weak signals this is critical — without waiting, we disconnect too early.
            try:
                resp_op = 0x01  # The enter-bootloader op code we sent
                status = await self._wait_for_response(resp_op, timeout=10.0)
                if status == 1:
                    self._log("Device confirmed jump. Rebooting into bootloader...")
                else:
                    self._log(f"Jump response status={status}, proceeding anyway.")
            except Exception:
                self._log("No jump response received (device may have rebooted already).")

            # Step 4: Disconnect (Android does waitFor(500) then disconnect for buttonless-without-bonds)
            await asyncio.sleep(0.5)
            try:
                await client.disconnect()
            except Exception:
                pass

        except Exception as e:
            if write_attempted:
                self._log(f"Device disconnected after jump command (expected): {e}")
            else:
                self._log(f"Jump connection failed: {e}", logging.WARNING)
                self._log("Will still scan for bootloader (device may already be in DFU mode).", logging.WARNING)

    async def perform_update(self, device: BLEDevice, max_retries: int = 3):
        self._log(f"Target Bootloader: {device.address}")
        self.reset_in_progress = False

        for attempt in range(max_retries):
            self._log(f"DFU connection attempt {attempt+1}/{max_retries}...")

            try:
                # Clear cache on first attempt — bootloader has different services than app mode
                client = await self._connect_with_retry(device, clear_cache=(attempt == 0))
                try:
                    self.client = client

                    await client.start_notify(DFU_CONTROL_POINT_UUID, self._notification_handler)
                    await asyncio.sleep(0.5)  # Allow device to settle after reboot before issuing commands

                    mtu = await self._setup_mtu()
                    self._log(f"Connected to Bootloader. MTU: {mtu}")

                    while not self.response_queue.empty(): self.response_queue.get_nowait()

                    # Start DFU
                    mode_name = _UPLOAD_MODE_NAMES.get(self.upload_mode, f"0x{self.upload_mode:02x}")
                    self._log(f"Firmware type: {mode_name} (mode=0x{self.upload_mode:02x})")
                    start_payload = bytearray([OP_CODE_START_DFU, self.upload_mode])
                    await client.write_gatt_char(DFU_CONTROL_POINT_UUID, start_payload, response=True)

                    if self.packet_delay > 0:
                        await asyncio.sleep(self.packet_delay)

                    size_payload = struct.pack('<III', self.sd_size, self.bl_size, self.app_size)

                    self._log(f"Sending sizes: SD={self.sd_size} BL={self.bl_size} App={self.app_size} bytes")
                    await client.write_gatt_char(DFU_PACKET_UUID, size_payload, response=False)

                    status = await self._wait_for_response(OP_CODE_START_DFU, timeout=60.0)
                    if status == 2:  # INVALID_STATE — stale DFU from previous attempt
                        self._log("Bootloader in INVALID_STATE, resetting and retrying...", logging.WARNING)
                        await client.write_gatt_char(DFU_CONTROL_POINT_UUID, bytearray([OP_CODE_RESET]), response=True)
                        raise DfuException("INVALID_STATE — reset sent, will retry")
                    if status != 1:
                        await client.write_gatt_char(DFU_CONTROL_POINT_UUID, bytearray([OP_CODE_RESET]), response=True)
                        raise DfuException(f"Start DFU sequence failed with status {status}")

                    # Init Packet
                    self._log("Sending Init Packet...")
                    await client.write_gatt_char(DFU_CONTROL_POINT_UUID, bytearray([OP_CODE_INIT_DFU_PARAMS, 0x00]), response=True)
                    await client.write_gatt_char(DFU_PACKET_UUID, self.dat_data, response=False)
                    await asyncio.sleep(0.1)  # Ensure WriteWithoutResponse is delivered before end-init command
                    await client.write_gatt_char(DFU_CONTROL_POINT_UUID, bytearray([OP_CODE_INIT_DFU_PARAMS, 0x01]), response=True)

                    status = await self._wait_for_response(OP_CODE_INIT_DFU_PARAMS)
                    if status != 1: raise DfuException(f"Init Packet failed. Status: {status}")

                    # PRN
                    if self.prn > 0:
                        self._log(f"Configuring PRN: {self.prn}")
                        prn_payload = bytearray([OP_CODE_PACKET_RECEIPT_NOTIF_REQ]) + struct.pack('<H', self.prn)
                        await client.write_gatt_char(DFU_CONTROL_POINT_UUID, prn_payload, response=True)

                    # Stream
                    self._log("Requesting Upload...")
                    await client.write_gatt_char(DFU_CONTROL_POINT_UUID, bytearray([OP_CODE_RECEIVE_FIRMWARE_IMAGE]), response=True)
                    await self._stream_firmware()

                    # Validate
                    self._log("Verifying Upload...")
                    flash_write_timeout = max(60.0, len(self.bin_data) / 50000) # Longer timeout for flash write completion - ~1s per 50KB
                    status = await self._wait_for_response(OP_CODE_RECEIVE_FIRMWARE_IMAGE, timeout=flash_write_timeout)
                    if status != 1: raise DfuException(f"Upload failed. Status: {status}")

                    self._log("Validating...")
                    await client.write_gatt_char(DFU_CONTROL_POINT_UUID, bytearray([OP_CODE_VALIDATE]), response=True)
                    status = await self._wait_for_response(OP_CODE_VALIDATE)
                    if status != 1: raise DfuException(f"Validation failed. Status: {status}")

                    # Reset
                    self._log("Activating & Resetting...")
                    self.reset_in_progress = True
                    await client.write_gatt_char(DFU_CONTROL_POINT_UUID, bytearray([OP_CODE_ACTIVATE_AND_RESET]), response=True)
                    self._log("DFU Complete.")
                    return # SUCCESS

                finally:
                    try:
                        await client.disconnect()
                    except Exception:
                        pass

            except Exception as e:
                if self.reset_in_progress:
                    self._log(f"Device disconnected during reset. Update Successful.")
                    return
                self._log(f"Attempt {attempt+1} failed: {e}", logging.ERROR)
                if attempt < max_retries - 1:
                    await asyncio.sleep(3.0)
                else:
                    raise e

    async def _stream_firmware(self):
        if not self.high_mtu:
            mtu = 23
        else:
            # Suppress warning when reading MTU for chunk calculation
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                mtu = self.client.mtu_size if self.client else 23
        chunk_size = max(mtu - 3, 20)  # ATT overhead, floor at 20
        self._log(f"Using chunk_size = {chunk_size}")
        self._last_progress_block = -1
        total_bytes = len(self.bin_data)
        packets_since_prn = 0
        self.bytes_sent = 0
        prn_timeout = max(3.0, self.prn * 0.3)  # Conservative: 0.3s/packet, min 3s
        self._log(f"PRN Timeout set to {prn_timeout:.2f} seconds")

        self._log(f"Uploading {total_bytes} bytes...")

        for i in range(0, total_bytes, chunk_size):
            chunk = self.bin_data[i : i + chunk_size]
            await self.client.write_gatt_char(DFU_PACKET_UUID, chunk, response=False)
            self.bytes_sent += len(chunk)
            packets_since_prn += 1

            pct = int((self.bytes_sent * 100) / total_bytes)

            last_pct = getattr(self, "_last_progress_pct", -1)
            if pct > last_pct:
                if self.progress_callback:
                    self.progress_callback(pct)
                self._last_progress_pct = pct

            if self.prn > 0 and packets_since_prn >= self.prn:
                self.pkg_receipt_event.clear()
                try:
                    await asyncio.wait_for(self.pkg_receipt_event.wait(), timeout=prn_timeout)
                except asyncio.TimeoutError:
                    self._log("PRN Timeout, continuing anyway...", logging.WARNING)
                packets_since_prn = 0

        if self.progress_callback:
            if getattr(self, "_last_progress_pct", -1) < 100:
                self.progress_callback(100)

async def scan_for_devices(adapter: str = None) -> List[BLEDevice]:
    """Returns a list of all found devices (simple scan)."""
    scanner = BleakScanner(adapter=adapter)
    return await scanner.discover(timeout=5.0)

async def find_device_by_name_or_address(name_or_address: str, force_scan: bool, adapter: str = None, service_uuid: str = None) -> BLEDevice:
    """
    Helper to find a specific device.
    """
    if not force_scan and not adapter:
        try:
            device = await BleakScanner.find_device_by_address(name_or_address, timeout=10.0)
            if device: return device
        except BleakError:
            pass

    scanner = BleakScanner(adapter=adapter)
    scanned_devices = await scanner.discover(timeout=5.0, return_adv=True)

    target = None

    for key, (d, adv) in scanned_devices.items():
        if d.address.upper() == name_or_address.upper():
            target = d; break

        adv_name = adv.local_name or d.name or ""
        if adv_name == name_or_address:
            target = d; break

        if not target and service_uuid:
            if service_uuid.lower() in [u.lower() for u in adv.service_uuids]:
                target = d; break

    if not target:
        raise DfuException("Device not found.")

    return target

async def find_any_device(identifiers: List[str], adapter: str = None, service_uuid: str = None, service_uuids: List[str] = None) -> BLEDevice:
    """
    Scans once and checks if ANY of the provided identifiers match found devices.
    Returns the first device that matches by address, name, or service UUID.
    Accepts either a single service_uuid or a list of service_uuids.
    """
    # Normalize to a list
    match_uuids = []
    if service_uuids:
        match_uuids = [u.lower() for u in service_uuids]
    elif service_uuid:
        match_uuids = [service_uuid.lower()]

    scanner = BleakScanner(adapter=adapter)
    scanned_devices = await scanner.discover(timeout=5.0, return_adv=True)

    for key, (d, adv) in scanned_devices.items():
        adv_name = (adv.local_name or d.name or "")
        adv_name_upper = adv_name.upper()
        adv_svc_uuids = [u.lower() for u in adv.service_uuids]

        # 1. Check service UUIDs (highest confidence — catches DFU bootloader regardless of name)
        if match_uuids:
            for mu in match_uuids:
                if mu in adv_svc_uuids:
                    return d

        # 2. Check address or name against all provided identifiers
        for identifier in identifiers:
            if d.address.upper() == identifier.upper():
                return d
            if adv_name_upper == identifier.upper():
                return d

    raise DfuException(f"No devices found matching: {identifiers}")
