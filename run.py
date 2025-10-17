"""
Simple startup script for the Suricata Rule Browser
"""
import uvicorn


def main():
    print("=" * 60)
    print("Starting Suricata Rule Browser")
    print("=" * 60)
    print("\nWeb Interface: http://localhost:8000")
    print("API Documentation: http://localhost:8000/docs")
    print("\nPress CTRL+C to stop the server\n")
    print("=" * 60)

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )


if __name__ == "__main__":
    main()
