export class HttpError extends Error {
  constructor(message, status, url, body) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.url = url;
    this.body = body;
  }
}

export async function getJson(url, { headers = {}, timeout = 18000 } = {}) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json",
        ...headers,
      },
      signal: controller.signal,
      redirect: "follow",
      referrerPolicy: "no-referrer",
    });

    const text = await response.text();
    let body = null;

    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
    }

    if (!response.ok) {
      throw new HttpError(
        `HTTP ${response.status}`,
        response.status,
        url,
        body
      );
    }

    return body;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error(`Request timed out after ${Math.round(timeout / 1000)}s`);
    }

    if (error instanceof TypeError) {
      throw new Error("Network or CORS request failed");
    }

    throw error;
  } finally {
    window.clearTimeout(timer);
  }
}

export function githubHeaders(token) {
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  return headers;
}

export function errorMessage(error) {
  if (error instanceof HttpError) {
    if (error.status === 401) {
      return "Authentication required or invalid credentials (HTTP 401).";
    }

    if (error.status === 403) {
      const detail =
        error.body && typeof error.body === "object" && error.body.message
          ? ` — ${error.body.message}`
          : "";
      return `Access denied or rate limited (HTTP 403)${detail}`;
    }

    if (error.status === 404) {
      return "No public record returned (HTTP 404).";
    }

    if (error.status === 429) {
      return "Provider rate limit reached (HTTP 429). Try again later.";
    }

    const detail =
      error.body && typeof error.body === "object" && error.body.message
        ? ` — ${error.body.message}`
        : "";

    return `${error.message}${detail}`;
  }

  if (error instanceof Error && error.message) {
    return error.message;
  }

  return "Unknown request failure.";
}
