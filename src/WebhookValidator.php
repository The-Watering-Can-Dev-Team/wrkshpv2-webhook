<?php

namespace WorkshopsV2;

use WP_Error;
use WP_REST_Request;

class WebhookValidator
{

    private string $secret;

    /**
     * @param string $secret
     */
    public function __construct(string $secret)
    {
        $this->secret = $secret;
    }

    /**
     * @param WP_REST_Request $request
     * @return true|WP_Error
     */
    function validate_from_wp_json(WP_REST_Request $request)
    {
        $signature  = $request->get_header('X-Workshop-Signature');
        if (!$signature) {
            return new WP_Error('missing_signature', 'Invalid signature', ['status' => 403]);
        }
        $payload    = file_get_contents('php://input');
        if (!$this->is_valid($payload, $signature)) {
            return new WP_Error('invalid_signature', 'Invalid signature', ['status' => 403]);
        }
        return true;
    }

    /**
     * @param string $payload
     * @param string $signature
     * @return bool
     */
    function is_valid(string $payload, string $signature): bool
    {
        $hash = hash_hmac('sha256', $payload, $this->secret);
        return hash_equals($hash, $signature);
    }
}