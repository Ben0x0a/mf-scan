CREATE TABLE conversation_message (
    client_conversation_id text not null,
    client_message_id integer not null,
    server_message_id integer,   -- server monotonically increasing id, nullable if pending message

    client_resolution_id integer, -- Not null. Intentionally not adding this as SQL constraint since we had null data
                                  -- in the past during internal testing.
    local_message_content_id integer, -- nullable if message wasn't created on this device
    message_content blob not null,
    message_state_type text not null,
    creation_timestamp integer not null,
    read_timestamp integer not null, -- timestamp when the message is first marked read by any participants
    local_message_references blob, -- if the message originates from the device we keep local media reference around to have stable local cache ids
    quoted_server_message_id integer, -- nullable if message is not a reply to another message or quoted_message_status is set to an unavailable status
    quoted_message_status integer, -- nullable if message is not a reply to another message
    latest_reaction_id integer, -- nullable each reaction has a unique ascending id per conversation. This is the latest id of all the reactions on this message. Optimization for the SQL expiry query.
    is_dryrun_eel_reencrypt_required integer not null default 0, -- This is a temporary field to test eel reencryption in dry-run mode. Will be remove in future
    last_decryption_failure integer, -- nullable or 0 if there is no decryption failure, otherwise set to last decryption failure even if message no longer pending decryption
    bundle_id text, -- nullable. If the message is part of a message bundle, this will contain the unique UUID associated with all bundled messages
    watermark_status integer, -- nullable
    created_on_device integer not null, -- bool. set to true if the message was created on this device
    epoch_number integer, -- set when message encrypted with Kraken protocol; otherwise NULL

    -- Columns below are not exposed outside of the storage layer and only used to optimize underlying queries
    -- They are populated from proto blobs, such as message metadata
    -- -------------------------------------------------------------------------------------------------------------- --
    is_saved integer not null, -- bool. set to true iff message_content.metadata().saved_by_size() > 0
    is_viewed_by_user integer not null, -- bool. set to true iff message.content.metadata().read_by() contains current user
    remote_media_count integer not null, -- size of the media reference list message.content.contents().media_reference_lists_size()
    content_type integer not null, -- type of the content as defined in message.content.contents().content_type()
    content_read_release_policy integer not null, -- type of the content read release policy as defined in message.content.release_policy()
    released_by_count integer not null, -- size of message.content.metadata().released_by_size() list
    sender_id text, -- message.content.sender_id()
    is_released_by_user integer not null, -- bool. true iff message is released by user,  message.content.metadata().released_by() contains current user id
    release_state integer, -- enum. Release state of the message. Starts optional, not set for conversations that don't send release messages or messages that don't require individual release.
    hidden_from_platform integer not null default 0, -- bool Should hide this message from platform. Read/Release watermark and save state can override this value.
    has_eel_re_encryption_requests integer not null, -- bool set to true iff message is eel encrypted and message.content.metadata().eel_re_encryption_inits() contains requests
    replies_count integer, -- a count of replies that the given message is quoted in. Null if unknown (not populated), otherwise zero if no replies
    post_open_viewing_policy int, -- set to the post open viewing policy defined by message.content.metadata().snap_post_open_viewing_policy(). Null indicates unknown (not populated since column addition)

    primary key(client_conversation_id, client_message_id),
    unique (client_conversation_id, server_message_id),

    foreign key(client_conversation_id) references conversation_identifier(client_conversation_id),
    foreign key(message_state_type) references message_state(state_type),
    foreign key(local_message_content_id) references local_message_content(local_message_content_id)
)