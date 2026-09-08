from __future__ import annotations

import argparse
import asyncio
import json

import websockets


async def verify(url: str, advances: int) -> dict:
    async with websockets.connect(url) as socket:
        await socket.recv()
        update = None
        for _ in range(advances):
            await socket.send(json.dumps({"seconds": 5}))
            update = json.loads(await socket.recv())
    inference = update["inference"]
    return {
        "type": update["type"],
        "warmup_states": inference["warmup_states"],
        "model_ready": inference["model_ready"],
        "forecast": inference["forecast"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify a local ShadowNet replay WebSocket.")
    parser.add_argument("url")
    parser.add_argument("--advances", type=int, default=13)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(verify(args.url, args.advances)), indent=2))
