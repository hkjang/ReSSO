-- id_token_hint names the account a relying party believes it is renewing, and
-- the authorization endpoint honoured it on one path only: the silent one,
-- where a session already in the browser is compared against it. A request the
-- hint did not match was parked here and the person sent to the login form —
-- and the parked request kept no trace of the hint, so whoever signed in at
-- that form received the code. The relying party asked about one account and
-- was handed another, with nothing in the response to say so.
--
-- Empty means no hint was sent, which is what every request written before this
-- column existed was, so an upgrade changes nothing for requests in flight.
ALTER TABLE authorization_requests
    ADD COLUMN IF NOT EXISTS id_token_hint_subject text NOT NULL DEFAULT '';
