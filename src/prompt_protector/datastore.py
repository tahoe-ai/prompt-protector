from google.cloud import datastore
import time

def store_message_in_db(user_input, system_response, channel_id, caught_by, rationale):
    """
    Store a message in Google Cloud Datastore.

    Args:
        user_input (str): The user's input text.
        system_response (str): The system's response text.
        channel_id (str): Identifier for the communication channel.
        caught_by (str): Indicator of what process caught the message for review.
        rationale (str): Reason why the message was caught.
    """
    # Initialize the Datastore client
    datastore_client = datastore.Client()

    # Create a key for a new entity in the 'Messages' kind
    new_entity_key = datastore_client.key('Messages')

    # Create a new entity
    new_entity = datastore.Entity(key=new_entity_key)

    # Set properties for the new entity
    new_entity.update({
        'user_input': user_input,
        'system_response': system_response,
        'channel_id': channel_id,
        'timestamp': time.time(),
        'caught_by': caught_by,
        'rationale': rationale
    })

    # Save the new entity to Datastore
    datastore_client.put(new_entity)

def retrieve_last_message(channel_id):
    """
    Retrieve the last message for a given channel from Google Cloud Datastore.

    Args:
        channel_id (str): Identifier for the communication channel.

    Returns:
        dict: The last message for the channel or None if there is no message.
    """
    # Initialize the Datastore client
    datastore_client = datastore.Client()

    # Create a query for the 'Messages' kind filtered by 'channel_id'
    query = datastore_client.query(kind='Messages')
    query.add_filter('channel_id', '=', channel_id)
    query.order = ['-timestamp']
    query.keys_only()

    # Execute the query
    results = list(query.fetch(limit=1))

    # Check if a result is found
    if results:
        # Retrieve the full entity using the key from the first result
        last_message_key = results[0]
        last_message = datastore_client.get(last_message_key)

        # Return the last message if it wasn't caught as a potential issue
        if last_message.get("caught_by") is None:
            return {
                'user_input': last_message['user_input'],
                'system_response': last_message['system_response'],
                'channel_id': last_message['channel_id'],
                'timestamp': last_message['timestamp'],
                'caught_by': last_message.get('caught_by'),
                'rationale': last_message.get('rationale')
            }
    return None
