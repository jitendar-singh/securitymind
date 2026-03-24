import sys
import asyncio
from secmind.agent import secmind

async def main(instruction):
    """
    Runs the secmind agent with the given instruction.
    """
    if not instruction:
        print("Please provide an instruction.")
        return

    # The agent.run method is async
    response = await secmind.run(instruction)
    print(response)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        instruction = " ".join(sys.argv[1:])
        asyncio.run(main(instruction))
    else:
        print("Usage: python run_agent.py <instruction>")

