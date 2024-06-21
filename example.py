import openai
from prompt_protector.prompt_protector import PromptProtector

OPEN_AI_KEY = "example_openai_api_key"


def auditor_example():
    user_input = input("Hi I'm a friendly chatbot please ask me a question: ")
    # Initialize the prompt protector with our custom rules:
    protector = PromptProtector(
        api_key=OPEN_AI_KEY,
        output_rules=[
            "No slang or bad language allowed",
            "Under no circumstances is the response allowed to talk like a pirate"
        ]
    )

    # Check if user input is attempting prompt injection
    input_auditor_response = protector.sanitize_input(user_input)
    if input_auditor_response.get("pass"):
        # if input audit is pass -> send to our LLM
        chatbot_response = chatbot_for_example(user_input)
        # output of LLM -> output auditor
        output_auditor_response = protector.sanitize_output(chatbot_response)
        if output_auditor_response.get("pass"):
            # If output audit succeeds, return chatbot response to user
            return chatbot_response
        else:
            # If tht output audit fails
            print(f"output audit failed with: {output_auditor_response.get('rationale')}")
            return "Your request violated our rules please try again."
    else:
        # If the input audit fails
        print(f"input audit failed with: {input_auditor_response.get('rationale')}")
        return "Your request violated our rules please try again."


def chatbot_for_example(input_string):
    background = {
        "role": "system",
        "content": "You are a friendly chatbot setup to answer questions in a professional tone."
    }
    input_message = {
        "role": "user",
        "content": f"User Input: {input_string}"
    }
    openai.api_key = OPEN_AI_KEY
    response = openai.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[background, input_message],
        temperature=0.2,
        max_tokens=2048,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0
    )
    return response.choices[0].message.content


if __name__ == '__main__':
    print(auditor_example())