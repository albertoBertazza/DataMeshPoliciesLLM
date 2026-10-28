import requests

def _build_local_chat_prompt(messages):
    """
    Convert OpenAI-style chat messages into the chat format
    expected by llama-server.

    Example:

        [
            {"role": "system", "content": "..."},
            {"role": "user", "content": "..."}
        ]

    becomes:

        <|im_start|>system
        ...
        <|im_end|>
        <|im_start|>user
        ...
        <|im_end|>
        <|im_start|>assistant
    """

    if not messages:
        raise ValueError( "messages cannot be empty for local LLM" )

    parts = []

    for message in messages:

        role = message.get( "role" )

        content = message.get( "content", "" )

        if role not in ( "system", "user", "assistant"):
            continue

        parts.append( f"<|im_start|>{role}\n" f"{content}\n" f"<|im_end|>" )

    parts.append( "<|im_start|>assistant\n" )

    return "\n".join( parts )

def llm_call( prompt=None, temperature=0.0, max_tokens=600, system_prompt=None, response_format=None, is_local=False, chat_url=None, client=None, model=None, messages=None):
    """
    Unified LLM call.

    Local:
        Uses llama-server /completion.

    External:
        Uses OpenAI-compatible chat.completions API.

    Parameters
    ----------
    prompt : str
        User prompt when messages are not supplied.

    messages : list
        OpenAI-style messages:

        [
            {
                "role": "system",
                "content": "..."
            },
            {
                "role": "user",
                "content": "..."
            }
        ]

    response_format : dict
        Example:

        {
            "type": "json_object"
        }
    """


    # ========================================================================
    # LOCAL LLAMA SERVER
    # ========================================================================

    if is_local:
        if chat_url is None:
            raise ValueError("chat_url is required when is_local=True")

        # Always create a local copy of the messages.
        if messages is not None:
            local_messages = [dict(message) for message in messages]
        else:
            if prompt is None:
                raise ValueError("prompt or messages is required")

            local_messages = []

            if system_prompt is not None:
                local_messages.append({
                    "role": "system",
                    "content": system_prompt,
                })

            local_messages.append({
                "role": "user",
                "content": prompt,
            })

        if not local_messages:
            raise ValueError("messages cannot be empty for local LLM")

        # Add JSON instructions before building the assistant prompt.
        if response_format == {"type": "json_object"}:
            json_instruction = (
                "Return ONLY valid JSON. "
                "Do not use markdown code fences. "
                "Do not include explanations outside the JSON."
            )

            # Add the instruction to the last user message.
            last_user_index = next(
                (
                    i for i in range(len(local_messages) - 1, -1, -1)
                    if local_messages[i].get("role") == "user"
                ),
                None,
            )

            if last_user_index is not None:
                local_messages[last_user_index]["content"] = (
                    local_messages[last_user_index].get("content", "")
                    + "\n\n"
                    + json_instruction
                )
            else:
                local_messages.append({
                    "role": "user",
                    "content": json_instruction,
                })

        local_prompt = _build_local_chat_prompt(local_messages)

        response = requests.post(
            chat_url + "/completion",
            json={
                "prompt": local_prompt,
                "temperature": temperature,
                "n_predict": max_tokens,
                "stop": ["<|im_end|>"],
            },
        )

        response.raise_for_status()
        data = response.json()

        print("LLAMA CONTENT:", repr(data.get("content")))
        print("LLAMA STOP TYPE:", data.get("stop_type"))
        print("LLAMA STOP:", data.get("stop"))
        print("LLAMA TOKENS PREDICTED:", data.get("tokens_predicted"))
        print("LLAMA RESPONSE KEYS:", list(data.keys()))

        if "content" not in data:
            raise ValueError(
                "Local LLM response does not contain 'content': " + str(data)
            )

        return data["content"].strip()

        if "content" not in data:
            raise ValueError(
                "Local LLM response does not contain 'content': "
                + str(data)
            )

        return data["content"].strip()



    # ========================================================================
    # OPENAI / EXTERNAL API
    # ========================================================================

    if client is None or model is None:

        raise ValueError( "client and model are required " "when is_local=False" )

    # ------------------------------------------------------------------------
    # Build messages if caller used old prompt/system_prompt interface.
    # ------------------------------------------------------------------------

    if messages is None:

        messages = []

        if system_prompt is not None:

            messages.append( { "role": "system", "content": system_prompt} )

        if prompt is not None:

            messages.append( { "role": "user", "content": prompt} )

    # ------------------------------------------------------------------------
    # OpenAI-compatible request
    # ------------------------------------------------------------------------

    kwargs = { "model": model, "temperature": temperature, "messages": messages}

    if response_format is not None:

        kwargs["response_format"] = response_format

    response = client.chat.completions.create( **kwargs )

    return response.choices[0].message.content
