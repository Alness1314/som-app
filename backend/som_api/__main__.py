import os
import uvicorn

if __name__ == "__main__":
    uvicorn.run("som_api.main:app", host="127.0.0.1", port=int(os.environ.get("SOM_PORT", "8765")), access_log=False)
