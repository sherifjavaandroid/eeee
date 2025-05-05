# debug_run.py
import sys
import os
import click
import logging
import time
from pathlib import Path

# Add the project root to the Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# Import after path is set
from src.core.scanner import MobileSecurityScanner
from src.core.analyzer import SecurityAnalyzer
from src.core.exploiter import ExploitEngine
from src.modules.reporting.report_generator import ReportGenerator
from src.utils.file_helper import setup_output_directories
from config.logging_config import setup_logging

@click.command()
@click.argument('app_path', type=click.Path(exists=True))
@click.option('--platform', type=click.Choice(['android', 'ios']), required=True)
@click.option('--mode', type=click.Choice(['quick', 'full', 'exploit']), default='full')
@click.option('--output', type=click.Path(), default='output')
@click.option('--verbose', is_flag=True)
def main(app_path, platform, mode, output, verbose):
    """Mobile Security Automation Tool"""

    # Setup logging with debug level
    setup_logging(True)  # Force verbose
    logger = logging.getLogger(__name__)

    # Add extra console logging for debugging
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    logging.getLogger().addHandler(console_handler)

    # Setup output directories
    logger.info("Setting up output directories...")
    setup_output_directories(output)

    try:
        logger.info(f"Starting security assessment of {app_path}")

        # Initialize scanner
        logger.info("Initializing scanner...")
        scanner = MobileSecurityScanner(app_path, platform)

        logger.info("Initializing analyzer...")
        analyzer = SecurityAnalyzer()

        # Run static analysis
        logger.info("Running static analysis...")
        start_time = time.time()

        try:
            static_results = scanner.run_static_analysis()
            elapsed_time = time.time() - start_time
            logger.info(f"Static analysis completed in {elapsed_time:.2f} seconds")
            logger.info(f"Static results: {static_results}")
        except Exception as e:
            logger.error(f"Static analysis failed with error: {e}", exc_info=True)
            raise

        # Run dynamic analysis if not in quick mode
        dynamic_results = {}
        if mode != 'quick':
            logger.info("Running dynamic analysis...")
            start_time = time.time()
            try:
                dynamic_results = scanner.run_dynamic_analysis()
                elapsed_time = time.time() - start_time
                logger.info(f"Dynamic analysis completed in {elapsed_time:.2f} seconds")
            except Exception as e:
                logger.error(f"Dynamic analysis failed: {e}", exc_info=True)
                # Continue even if dynamic analysis fails

        # Analyze results
        logger.info("Analyzing results...")
        vulnerabilities = analyzer.analyze_results(static_results, dynamic_results)
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities")

        # Generate exploits if requested
        exploits = []
        if mode == 'exploit' and vulnerabilities:
            logger.info("Generating exploits...")
            exploit_engine = ExploitEngine()
            exploits = exploit_engine.generate_exploits(vulnerabilities)

        # Generate report
        logger.info("Generating report...")
        report_generator = ReportGenerator()
        report_path = report_generator.generate_report(
            app_path=app_path,
            platform=platform,
            vulnerabilities=vulnerabilities,
            exploits=exploits,
            output_dir=output
        )

        logger.info(f"Assessment complete. Report saved to: {report_path}")

    except Exception as e:
        logger.error(f"Error during assessment: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()