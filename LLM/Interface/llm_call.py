import requests

MODEL_PROMPT_WRAPPER = """
<|im_start|>system
You are a helpful assistant that explains Trino authorization rules.
<|im_end|>
<|im_start|>user
{prompt}
<|im_end|>
<|im_start|>assistant
"""


def llm_call(prompt,temperature=0.0,max_tokens=600,system_prompt=None,response_format=None,is_local=False, chat_url=None,client=None,model=None):
    """
    Unified LLM call.

    Parameters
    ----------
    prompt : str
        User prompt.

    temperature : float
        Sampling temperature.

    max_tokens : int
        n_predict for local, max_tokens for API (or ignored if the API uses defaults).

    system_prompt : str | None
        Only used for chat APIs.

    response_format : dict | None
        Passed directly to the API if provided.

    is_local : bool
        True -> llama-server
        False -> external API

    chat_url : str
        llama-server URL (required if is_local=True).

    client :
        OpenAI-compatible client (required if is_local=False).

    model : str
        Model name (required if is_local=False).
    """

    if is_local:
        if chat_url is None:
            raise ValueError("chat_url is required when is_local=True")

        response = requests.post(
            chat_url + "/completion",
            json={
                "prompt": MODEL_PROMPT_WRAPPER.format(prompt=prompt),
                "temperature": temperature,
                "n_predict": max_tokens,
                "stop": ["User:", "Rule:"],
            },
        )

        response.raise_for_status()

        data = response.json()

        # print("\n[RAW LLAMA RESPONSE]")
        # print(data)

        return data["content"]

    # External API
    if client is None or model is None:
        raise ValueError("client and model are required when is_local=False")

    temperatureInt=int(temperature)
    kwargs = {
        "model": model,
        "temperature": temperatureInt,
        "messages": [],
    }

    if response_format is not None:
        kwargs["response_format"] = response_format

    if system_prompt is not None:
        kwargs["messages"].append(
            {
                "role": "system",
                "content": system_prompt,
            }
        )

    kwargs["messages"].append(
        {
            "role": "user",
            "content": prompt,
        }
    )

    response = client.chat.completions.create(**kwargs)

    return response.choices[0].message.content