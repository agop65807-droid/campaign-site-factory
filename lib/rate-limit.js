async function checkRateLimit(client, key, max = 10, windowSeconds = 900) {
  const { data, error } = await client.rpc('factory_check_rate_limit', {
    p_key: key,
    p_max: max,
    p_window_seconds: windowSeconds
  });

  if (error) {
    console.error('Rate limit error:', error.message);
    return { allowed: false, retryAfter: 60 };
  }

  const row = Array.isArray(data) ? data[0] : data;
  return {
    allowed: row?.allowed === true,
    retryAfter: row?.retry_after ?? 0
  };
}

module.exports = { checkRateLimit };
