import sys

from snyk_ai import Model, create_model, Models


def chatbot(model: Model):
    print(f"Using model: {model.name}")
    print("Chatbot ready. Type 'exit' to quit.")

    while True:
        try:
            user_input = input("\nYou: ").strip()
            if user_input.lower() == "exit":
                print("Goodbye!")
                break
            if not user_input:
                continue

            response = model.generate(user_input)
            print(f"\nAssistant: {response}")

        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"\nError: {e}")


def main():
    if model_spec := sys.argv[1] if len(sys.argv) > 1 else None:
        try:
            model = create_model(model_spec)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        model = Models.Llama_3_2

    chatbot(model)


if __name__ == "__main__":
    main()
