import aiohttp
import asyncio
import os

URL = "http://127.0.0.1:8080/completion"

async def ask_llm(prompt, history):
    full_prompt = ""

    for user, assistant in history:
        full_prompt += f"User: {user}\nAssistant: {assistant}\n"

    full_prompt += f"User: {prompt}\nAssistant:"

    payload = {
        "prompt": full_prompt,
        "n_predict": 1024,
        "temperature": 0.7,
        "stop": ["User:"]
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(URL, json=payload) as response:
            response.raise_for_status()
            return await response.json()  # Await the coroutine to get the JSON data

async def main():
    print("💬 Local LLM Chatbot (type 'exit' to quit)\n")

    history = []

    while True:
        user_input = input("You: ").strip()

        if user_input.lower() in ["exit", "quit"]:
            break

        prompt=user_input

        add_files = input("Do you want to share files with the assistant? (s/yes to share): ").strip()
        # Ask if the user needs to share files
        if add_files.lower() in ("s", "yes"):
            print("\nYou need to share files. Please provide the paths of the files.")
            file_paths = []
            while True:
                file_path = input("Enter file path (or 'done' to finish): ").strip()
                if file_path.lower() == "done":
                    break
                if os.path.isfile(file_path):
                    file_paths.append(file_path)
                else:
                    print("File not found. Please try again.")
            if file_paths:
                # Read the contents of the files and add them to the prompt
                file_contents = []
                for file_path in file_paths:
                    with open(file_path, 'r', encoding='utf-8') as file:
                        file_contents.append(f"--- {file_path} ---\n")
                        file_contents.append(file.read())

                prompt += "\n\nFile contents:\n" + "\n\n".join(file_contents)
                print("\nFiles added to the prompt.\n")
                print("Prompt with file contents:\n", prompt)

        try:
            reply = await ask_llm(prompt, history)
            reply_content = reply["content"].strip()
        except Exception as e:
            print("Error:", e)
            continue
        print("\nBot:", reply_content, "\n")

        history.append((prompt, reply_content))

if __name__ == "__main__":
    asyncio.run(main())
