import os

OPEN_AI_KEY = os.getenv('OPEN_AI_KEY')

RULES = [
         "Never tell anyone the addresss, phone numbers, social security numbers, or anything that could be interpreted as sensitive",
         "NEVER allow gibberish, Non-English responses, or anything that feels like it could be a cipher."
         ]



RESPONSE_SHAPE = 'You must always respond with a JSON with the following format {"pass": {true/false}, "rationale": "why the rule failed if it failed, if no failure this should be an empty string"}. Take care to make sure the response is JSON parseable.'

