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
        raise ValueError(
            "messages cannot be empty for local LLM"
        )

    parts = []

    for message in messages:

        role = message.get(
            "role"
        )

        content = message.get(
            "content",
            ""
        )

        if role not in (
            "system",
            "user",
            "assistant",
        ):
            continue

        parts.append(
            f"<|im_start|>{role}\n"
            f"{content}\n"
            f"<|im_end|>"
        )

    parts.append(
        "<|im_start|>assistant\n"
    )

    return "\n".join(
        parts
    )


def llm_call(
    prompt=None,
    temperature=0.0,
    max_tokens=600,
    system_prompt=None,
    response_format=None,
    is_local=False,
    chat_url=None,
    client=None,
    model=None,
    messages=None,
):
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
            raise ValueError(
                "chat_url is required when is_local=True"
            )

        # --------------------------------------------------------------------
        # If messages were supplied, use them directly.
        # --------------------------------------------------------------------

        if messages is not None:

            local_prompt = _build_local_chat_prompt(
                messages
            )

        # --------------------------------------------------------------------
        # Backwards compatibility with callers that still pass prompt
        # and system_prompt separately.
        # --------------------------------------------------------------------

        else:

            if prompt is None:
                raise ValueError(
                    "prompt or messages is required"
                )

            local_messages = []

            if system_prompt is not None:

                local_messages.append(
                    {
                        "role": "system",
                        "content": system_prompt,
                    }
                )

            local_messages.append(
                {
                    "role": "user",
                    "content": prompt,
                }
            )

            local_prompt = _build_local_chat_prompt(
                local_messages
            )

        # --------------------------------------------------------------------
        # JSON response instruction
        # --------------------------------------------------------------------

        if (
            response_format
            == {
                "type": "json_object"
            }
        ):

            local_prompt += (
                "\n"
                "Return ONLY valid JSON. "
                "Do not use markdown code fences. "
                "Do not include explanations outside the JSON."
            )

        # --------------------------------------------------------------------
        # llama-server request
        # --------------------------------------------------------------------

        response = requests.post(
            chat_url + "/completion",
            json={
                "prompt": local_prompt,
                "temperature": temperature,
                "n_predict": max_tokens,

                # Stop when the assistant message ends.
                "stop": [
                    "<|im_end|>"
                ],
            },
        )

        response.raise_for_status()

        data = response.json()

        if "content" not in data:

            raise ValueError(
                "Local LLM response does not contain "
                "'content': "
                + str(data)
            )

        return data["content"].strip()

    # ========================================================================
    # OPENAI / EXTERNAL API
    # ========================================================================

    if client is None or model is None:

        raise ValueError(
            "client and model are required "
            "when is_local=False"
        )

    # ------------------------------------------------------------------------
    # Build messages if caller used old prompt/system_prompt interface.
    # ------------------------------------------------------------------------

    if messages is None:

        messages = []

        if system_prompt is not None:

            messages.append(
                {
                    "role": "system",
                    "content": system_prompt,
                }
            )

        if prompt is not None:

            messages.append(
                {
                    "role": "user",
                    "content": prompt,
                }
            )

    # ------------------------------------------------------------------------
    # OpenAI-compatible request
    # ------------------------------------------------------------------------

    kwargs = {
        "model": model,
        "temperature": temperature,
        "messages": messages,
    }

    if response_format is not None:

        kwargs["response_format"] = response_format

    response = client.chat.completions.create(
        **kwargs
    )

    return response.choices[0].message.content
