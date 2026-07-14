import requests

URL = "http://127.0.0.1:8080/completion"

def ask_llm(prompt, history):
    # build a simple chat-style prompt
    full_prompt = ""

    for user, assistant in history:
        full_prompt += f"User: {user}\nAssistant: {assistant}\n"

    full_prompt += f"User: {prompt}\nAssistant:"

    payload = {
        "prompt": full_prompt,
        "n_predict": 300,
        "temperature": 0.7,
        "stop": ["User:"]
    }

    response = requests.post(URL, json=payload)
    response.raise_for_status()

    return response.json()["content"].strip()


def main():
    print("💬 Local LLM Chatbot (type 'exit' to quit)\n")

    history = []

    while True:
        user_input = input("You: ").strip()

        if user_input.lower() in ["exit", "quit"]:
            break

        try:
            reply = ask_llm(user_input, history)
        except Exception as e:
            print("Error:", e)
            continue

        print("\nBot:", reply, "\n")

        history.append((user_input, reply))


if __name__ == "__main__":
    main()