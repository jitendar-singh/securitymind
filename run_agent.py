import sys
import asyncio

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types as genai_types

from secmind.agent import secmind


session_service = InMemorySessionService()


async def main(instruction):
    if not instruction:
        print("Please provide an instruction.")
        return

    session = await session_service.create_session(
        app_name="secmind", user_id="cli"
    )
    runner = Runner(
        agent=secmind,
        app_name="secmind",
        session_service=session_service,
    )
    content = genai_types.Content(
        role="user",
        parts=[genai_types.Part(text=instruction)],
    )

    async for event in runner.run_async(
        user_id="cli", session_id=session.id, new_message=content
    ):
        if hasattr(event, "content") and event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, "text") and part.text:
                    print(part.text, end="", flush=True)
    print()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        instruction = " ".join(sys.argv[1:])
        asyncio.run(main(instruction))
    else:
        print("Usage: python run_agent.py <instruction>")
