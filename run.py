"""
============================================================================
PHISHING GUARDIAN — APPLICATION ENTRY POINT
============================================================================
Start the application: python run.py

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn
from app.core.config import settings, verify_configuration


def print_startup_banner():
    """Display startup information."""
    config_status = verify_configuration()

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🛡️  {settings.APP_NAME} v{settings.APP_VERSION}                          ║
║   Zero-Budget Phishing Email Analysis Platform               ║
║                                                              ║
║   Author: Dr. Erik                                           ║
║   License: MIT (Free for all uses)                            ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║   ✅ COMPLETELY FREE SOURCES (No API Key Needed):            ║
║      • PhishTank — Community phishing database               ║
║      • OpenPhish — AI-detected phishing URLs                 ║
║      • URLScan.io — URL behavior analysis                    ║
║      • WHOIS — Domain registration lookup                    ║
║                                                              ║
║   🔑 OPTIONAL API KEYS (Free tiers, all optional):           ║
║      • VirusTotal — {'✅ Configured' if settings.VT_API_KEY else '❌ Not set (500 free req/day)'}                       ║
║      • AbuseIPDB — {'✅ Configured' if settings.ABUSEIPDB_API_KEY else '❌ Not set (1000 free checks/day)'}              ║
║      • Google Safe Browsing — {'✅ Configured' if settings.GSB_API_KEY else '❌ Not set (10,000 free req/day)'}          ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║   🌐 Starting server at: http://{settings.APP_HOST}:{settings.APP_PORT}                  ║
║   📊 API Documentation: http://{settings.APP_HOST}:{settings.APP_PORT}/docs              ║
║   🏥 Health Check: http://{settings.APP_HOST}:{settings.APP_PORT}/api/v1/health          ║
║                                                              ║
║   📋 Open your browser and start analyzing emails!           ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)


def main():
    """Start the FastAPI application."""
    print_startup_banner()

    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.is_development,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=settings.is_development,
    )


if __name__ == "__main__":
    main()