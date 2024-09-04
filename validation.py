# validation.py

def validate_input(message):
    allowed_characters = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?;:")
    return ''.join(filter(lambda x: x in allowed_characters, message))

