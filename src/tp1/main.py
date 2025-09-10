from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.report import Report
from src.tp1.utils.branding import print_banner  # ← NEW


def main():
    print_banner()  
    logger.info("Starting IDS/IPS...")

    capture = Capture()
    logger.info("Interface sélectionnée: %s", capture.interface)  # ← confirmation claire

    capture.capture_trafic()
    capture.analyse("tcp")
    summary = capture.get_summary()

    filename = "reports\\mon_rapport.pdf" 
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)

    logger.info("Report generated: %s", filename)
