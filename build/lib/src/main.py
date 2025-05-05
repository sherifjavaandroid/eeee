#!/usr/bin/env python3
import click
import sys
import logging
from pathlib import Path

@click.command()
@click.argument('app_path', type=click.Path(exists=True))
@click.option('--platform', type=click.Choice(['android', 'ios']), required=True)
@click.option('--mode', type=click.Choice(['quick', 'full', 'exploit']), default='full')
@click.option('--output', type=click.Path(), default='output')
@click.option('--verbose', is_flag=True)
def main(app_path, platform, mode, output, verbose):
    """Mobile Security Automation Tool"""

    # Import inside function to avoid circular imports
    try:
        # Try relative imports first (for development)
        from .core.scanner import MobileSecurityScanner
        from .core.analyzer import SecurityAnalyzer
        from .core.exploiter import ExploitEngine
        from .modules.reporting.report_generator import ReportGenerator
        from .utils.file_helper import setup_output_directories
        from ..config.logging_config import setup_logging
    except (ImportError, ValueError):
        try:
            # Try absolute imports (when running as script)
            from src.core.scanner import MobileSecurityScanner
            from src.core.analyzer import SecurityAnalyzer
            from src.core.exploiter import ExploitEngine
            from src.modules.reporting.report_generator import ReportGenerator
            from src.utils.file_helper import setup_output_directories
            from config.logging_config import setup_logging
        except ImportError:
            # If installed as package
            from mobile_security_scanner.core.scanner import MobileSecurityScanner
            from mobile_security_scanner.core.analyzer import SecurityAnalyzer
            from mobile_security_scanner.core.exploiter import ExploitEngine
            from mobile_security_scanner.modules.reporting.report_generator import ReportGenerator
            from mobile_security_scanner.utils.file_helper import setup_output_directories
            from mobile_security_scanner.config.logging_config import setup_logging

    # Setup logging
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    # Setup output directories
    setup_output_directories(output)

    try:
        logger.info(f"Starting security assessment of {app_path}")

        # Initialize scanner
        scanner = MobileSecurityScanner(app_path, platform)
        analyzer = SecurityAnalyzer()

        # Run static analysis
        logger.info("Running static analysis...")
        static_results = scanner.run_static_analysis()

        # Run dynamic analysis if not in quick mode
        dynamic_results = {}
        if mode != 'quick':
            logger.info("Running dynamic analysis...")
            dynamic_results = scanner.run_dynamic_analysis()

        # Analyze results
        vulnerabilities = analyzer.analyze_results(static_results, dynamic_results)

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
        logger.error(f"Error during assessment: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()