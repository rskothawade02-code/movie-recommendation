import os
import sys
import uvicorn

if __name__ == "__main__":
    # Support custom port via CLI argument or environment variable, defaulting to 8001 to prevent port collision with SentinelRCA (8000)
    port = int(os.environ.get("PORT", sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8001))
    print("\n" + "=" * 55)
    print("  [BollyWise AI] Movie Recommendation System")
    print("  Serving React UI + FastAPI Backend")
    print(f"  Open in browser: http://127.0.0.1:{port}")
    print("=" * 55 + "\n")
    uvicorn.run("backend.server:app", host="127.0.0.1", port=port, reload=False)
