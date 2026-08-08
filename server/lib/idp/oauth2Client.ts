import * as arctic from "arctic";

export class PangolinOAuth2Client extends arctic.OAuth2Client {
    private _clientPassword: string | null;
    private _redirectURI: string | null;

    constructor(
        clientId: string,
        clientPassword: string | null,
        redirectURI: string | null
    ) {
        super(clientId, clientPassword, redirectURI);
        this._clientPassword = clientPassword;
        this._redirectURI = redirectURI;
    }

    override async validateAuthorizationCode(
        tokenEndpoint: string,
        code: string,
        codeVerifier: string | null
    ): Promise<arctic.OAuth2Tokens> {
        if (this._clientPassword === null) {
            return super.validateAuthorizationCode(
                tokenEndpoint,
                code,
                codeVerifier
            );
        }

        const body = new URLSearchParams();
        body.set("grant_type", "authorization_code");
        body.set("code", code);
        if (this._redirectURI !== null) {
            body.set("redirect_uri", this._redirectURI);
        }
        if (codeVerifier !== null) {
            body.set("code_verifier", codeVerifier);
        }
        body.set("client_id", this.clientId);

        const request = new Request(tokenEndpoint, {
            method: "POST",
            body: new TextEncoder().encode(body.toString())
        });
        request.headers.set(
            "Content-Type",
            "application/x-www-form-urlencoded"
        );
        request.headers.set("Accept", "application/json");
        request.headers.set("User-Agent", "arctic");

        const bytes = new TextEncoder().encode(
            `${this.clientId}:${this._clientPassword}`
        );
        const base64 = Buffer.from(bytes).toString("base64");
        request.headers.set("Authorization", `Basic ${base64}`);

        const response = await fetch(request);
        if (response.status === 400 || response.status === 401) {
            let data: unknown;
            try {
                data = await response.json();
            } catch {
                throw new arctic.UnexpectedResponseError(response.status);
            }
            if (typeof data !== "object" || data === null) {
                throw new arctic.UnexpectedErrorResponseBodyError(
                    response.status,
                    data
                );
            }
            if ("error" in data && typeof data.error === "string") {
                throw new arctic.OAuth2RequestError(
                    data.error,
                    "error_description" in data &&
                    typeof data.error_description === "string"
                        ? data.error_description
                        : null,
                    "error_uri" in data && typeof data.error_uri === "string"
                        ? data.error_uri
                        : null,
                    "state" in data && typeof data.state === "string"
                        ? data.state
                        : null
                );
            }
            throw new arctic.UnexpectedErrorResponseBodyError(
                response.status,
                data
            );
        }

        if (response.status === 200) {
            let data: unknown;
            try {
                data = await response.json();
            } catch {
                throw new arctic.UnexpectedResponseError(response.status);
            }
            if (typeof data !== "object" || data === null) {
                throw new arctic.UnexpectedErrorResponseBodyError(
                    response.status,
                    data
                );
            }
            return new arctic.OAuth2Tokens(data as Record<string, unknown>);
        }

        if (response.body !== null) {
            await response.body.cancel();
        }
        throw new arctic.UnexpectedResponseError(response.status);
    }
}
