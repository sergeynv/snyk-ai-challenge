import argparse
import sys
from pathlib import Path

from snyk_ai import create_model
from snyk_ai.agent import Agent
from snyk_ai.utils.log import log, set_verbose


def run(agent: Agent):
    log("Running...")

    # we are only handling standalone queries (no follow-up questions);
    # but we are allowing the user to submit another question after answering one
    # (mostly because initializing vector DB takes a while, otherwise we could
    # just exit() after answering and start another process for the next question)
    while True:
        try:
            user_input = input("\nQ: ").strip()
            if user_input.lower() == "exit":
                print("Goodbye!")
                break
            if not user_input:
                continue
            print()

            response = agent.process_user_query(user_input)
            print(f"\nA: {response}")
            print(f"\n{'-' * 10}")

        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"\nError: {e}")



def main():
    parser = argparse.ArgumentParser(description="Security vulnerability assistant")
    parser.add_argument("data_dir", type=Path, help="Path to data directory")
    parser.add_argument(
        "--model", "-m",
        default="ollama:llama3.2",
        help="Model spec (default: ollama:llama3.2)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )
    args = parser.parse_args()

    set_verbose(args.verbose)

    # validate data_dir
    advisories_dir = args.data_dir / "advisories"
    csv_dir = args.data_dir / "csv"

    if not advisories_dir.is_dir():
        print(f"🛑 Error: {advisories_dir} not found")
        sys.exit(1)
    if not csv_dir.is_dir():
        print(f"🛑 Error: {csv_dir} not found")
        sys.exit(1)

    try:
        model = create_model(args.model)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    log(f"Using model: {model.name}")
    log("Initializing agent...")

    agent = Agent(
        advisories_dir,
        csv_dir,
        router_model=model,
        advisories_rag_model=model,
        code_summarizing_model=model,
        db_query_model=model,
        synthesizer_model=model,
    )

    log("Agent initialized")

    run(agent)


if __name__ == "__main__":
    main()
