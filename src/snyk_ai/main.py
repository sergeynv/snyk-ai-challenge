import argparse
import sys
from pathlib import Path

from snyk_ai import create_model
from snyk_ai.agent import Agent


def chatbot(agent: Agent):
    while True:
        try:
            user_input = input("\nQ: ").strip()
            if not user_input:
                continue

            response = agent.process_user_query(user_input)
            print(f"\nA: {response}")

        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"\nError: {e}")
        break


def main():
    parser = argparse.ArgumentParser(description="Security vulnerability chatbot")
    parser.add_argument("data_dir", type=Path, help="Path to data directory")
    parser.add_argument(
        "model",
        nargs="?",
        default="ollama:llama3.2",
        help="Model spec (default: ollama:llama3.2)",
    )
    args = parser.parse_args()

    # Validate data_dir
    advisories_dir = args.data_dir / "advisories"
    csv_dir = args.data_dir / "csv"

    if not advisories_dir.is_dir():
        print(f"Error: {advisories_dir} not found")
        sys.exit(1)
    if not csv_dir.is_dir():
        print(f"Error: {csv_dir} not found")
        sys.exit(1)

    try:
        model = create_model(args.model)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"Using model: {model.name}")
    print("Initializing agent...")
    agent = Agent(
        advisories_dir,
        csv_dir,
        router_model=model,
        advisories_rag_model=model,
        code_summarizing_model=model,
        db_query_model=model,
    )
    chatbot(agent)


if __name__ == "__main__":
    main()
