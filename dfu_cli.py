#!/usr/bin/env python3
# --- START OF FILE dfu_cli.py ---

import asyncio
import argparse
import logging
import sys
import time
import platform


# Update import to include the new find_any_device function
from dfu_lib import NordicLegacyDFU, find_any_device, DfuException, DFU_SERVICE_UUID, SECURE_DFU_SERVICE_UUID

# --- Custom Logger for CLI ---
class MsFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        t = time.strftime("%H:%M:%S", ct)
        return f"{t}.{int(record.msecs):03d}"

    def format(self, record):
        timestamp = self.formatTime(record)
        msg = record.getMessage()
        return f"{timestamp}  {msg}"

logger = logging.getLogger("DFU_CLI")

def cli_progress_handler(pct):
    sys.stdout.write(f"\rUploading: {pct}%")
    sys.stdout.flush()
    if pct == 100:
        sys.stdout.write("\n")

async def main():
    parser = argparse.ArgumentParser(description="Nordic Semi Buttonless Legacy DFU Utility (CLI)")
    parser.add_argument("file", help="Path to the ZIP firmware file")

    # Changed: nargs='+' allows multiple arguments to be collected into a list
    parser.add_argument("device", nargs='+', help="Device Name(s) or BLE Address(es). You can provide multiple.")

    parser.add_argument("--scan", action="store_true", help="Force scan even if address is provided")
    parser.add_argument("--adapter", default=None, help="Bluetooth Adapter interface (Linux: hci0)")
    parser.add_argument("--prn", type=int, default=8, help="PRN interval (default 8)")
    parser.add_argument("--delay", type=float, default=0.4, help="Start/Size Delay (default 0.4s)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logs")
    parser.add_argument("--high-mtu", action="store_true",
                        help="Enable high-MTU negotiation for faster transfers (disabled by default).")

    # New Arguments
    parser.add_argument("--wait", action="store_true", help="Loop indefinitely until one of the target devices is found")
    parser.add_argument("--retry", type=int, default=3, help="Number of DFU connection retries (default 3)")

    args = parser.parse_args()

    handler = logging.StreamHandler()
    if args.verbose:
        handler.setFormatter(MsFormatter())
        logger.setLevel(logging.DEBUG)
        logging.getLogger("bleak").setLevel(logging.WARNING)
        logging.getLogger("DFU_LIB").setLevel(logging.DEBUG)
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
        logger.setLevel(logging.INFO)
        logging.getLogger("bleak").setLevel(logging.ERROR)
        logging.getLogger("DFU_LIB").setLevel(logging.INFO)

    logger.addHandler(handler)
    logging.getLogger("DFU_LIB").addHandler(handler) # Attach handler to lib logger

    try:
        high_mtu = args.high_mtu
        if platform.system() == "Darwin":
            if high_mtu:
                logger.warning("macOS detected: high-MTU is not supported and will be ignored.")
            high_mtu = False

        # Pass None for log_callback so the library uses the standard logger configured above
        dfu = NordicLegacyDFU(args.file, args.prn, args.delay, adapter=args.adapter,
                               high_mtu=high_mtu, progress_callback=cli_progress_handler)
        dfu.parse_zip()

        logger.info(f"Scanning for target(s): {args.device}...")

        # --- WAIT / SCAN Loop ---
        app_device = None
        while True:
            try:
                # Use find_any_device to check all inputs in a single scan cycle
                app_device = await find_any_device(args.device, adapter=args.adapter)
                logger.info(f"Found target: {app_device.name} ({app_device.address})")
                break # Found!
            except DfuException:
                if args.wait:
                    logger.info("No devices found. Retrying scan...")
                    await asyncio.sleep(2.0)
                    continue
                else:
                    logger.error(f"Could not find any of: {args.device}")
                    sys.exit(1)

        await dfu.jump_to_bootloader(app_device)

        logger.info("Waiting for bootloader to appear...")
        await asyncio.sleep(3.0)

        # Build candidate identifiers: standard Nordic names + MAC+1 hint
        bootloader_identifiers = ["DfuTarg", "DFU"]
        original_mac = app_device.address
        if ":" in original_mac and len(original_mac) == 17:
            try:
                prefix = original_mac[:-2]
                last_byte = int(original_mac[-2:], 16)
                last_byte = (last_byte + 1) & 0xFF
                bootloader_mac_hint = f"{prefix}{last_byte:02X}"
                bootloader_identifiers.append(bootloader_mac_hint)
            except Exception:
                pass

        bootloader_device = None
        max_bootloader_wait_s = 30
        scan_interval_s = 3.0
        scan_attempts = int(max_bootloader_wait_s / scan_interval_s)
        for attempt in range(scan_attempts):
            logger.info(f"Scanning for Bootloader... (attempt {attempt + 1}/{scan_attempts})")
            try:
                bootloader_device = await find_any_device(bootloader_identifiers, adapter=args.adapter, service_uuids=[DFU_SERVICE_UUID, SECURE_DFU_SERVICE_UUID])
                break
            except DfuException:
                if attempt < scan_attempts - 1:
                    await asyncio.sleep(scan_interval_s)

        if not bootloader_device:
            raise DfuException(f"Could not locate DFU Bootloader device after {max_bootloader_wait_s}s.")

        # Pass the custom retry count here
        await dfu.perform_update(bootloader_device, max_retries=args.retry)

    except KeyboardInterrupt:
        logger.info("\nOperation Cancelled by User.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())