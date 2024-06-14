import aiohttp
import json
import openai
import time
from .settings import OPEN_AI_KEY


def feed_input_to_chat_gpt(input_string, last_message):
    messages_list = []
    if last_message is not None:
        last_user_message = {
            "role": "user",
            "content": last_message.get("user_input")
        }
        messages_list.append(last_user_message)
        last_gpt_message = {
            "role": "assistant",
            "content": last_message.get("system_response")
        }
        messages_list.append(last_gpt_message)
    input_message = {
        "role": "user",
        "content": input_string
    }
    messages_list.append(input_message)
    #print(f'messages list: {messages_list}')
    start = time.time()
    openai.api_key = OPEN_AI_KEY
    response = openai.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=messages_list,
        temperature=0.2,
        max_tokens=2048,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0
    )
    end = time.time()
    # Debug statements
    #print(f"Time spent in initial response: {end - start}")
    #print(f"initial response: {response.choices[0].message.content}")
    return response.choices[0].message.content

def prepare_messages(input_string, last_message):
    """
    Prepare the messages payload for the OpenAI API based on the user input and the last message.

    Args:
        input_string (str): The user's input string.
        last_message (dict): The last message exchanged in the conversation, if any.

    Returns:
        list: A list of message objects for the OpenAI API.
    """
    messages_list = []
    # Example: Add your system, previous conversation messages here
    # This function needs to be implemented based on how you want to construct
    # the conversation context for the API call.
    
    return messages_list
