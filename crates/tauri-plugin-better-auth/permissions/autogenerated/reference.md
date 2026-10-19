## Default Permission

Browser sign-in, the cached session, sign-out, and authenticated requests through the
auth bridge. The session token is never returned to the webview: no command reads it.

#### This default permission set includes the following:

- `allow-request-auth`
- `allow-authenticate`
- `allow-cancel-auth`
- `allow-get-session`
- `allow-sign-out`
- `allow-fetch`
- `allow-fetch-cancel`

## Permission Table

<table>
<tr>
<th>Identifier</th>
<th>Description</th>
</tr>


<tr>
<td>

`better-auth:allow-authenticate`

</td>
<td>

Enables the authenticate command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`better-auth:deny-authenticate`

</td>
<td>

Denies the authenticate command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`better-auth:allow-cancel-auth`

</td>
<td>

Enables the cancel_auth command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`better-auth:deny-cancel-auth`

</td>
<td>

Denies the cancel_auth command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`better-auth:allow-fetch`

</td>
<td>

Enables the fetch command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`better-auth:deny-fetch`

</td>
<td>

Denies the fetch command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`better-auth:allow-fetch-cancel`

</td>
<td>

Enables the fetch_cancel command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`better-auth:deny-fetch-cancel`

</td>
<td>

Denies the fetch_cancel command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`better-auth:allow-get-session`

</td>
<td>

Enables the get_session command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`better-auth:deny-get-session`

</td>
<td>

Denies the get_session command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`better-auth:allow-request-auth`

</td>
<td>

Enables the request_auth command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`better-auth:deny-request-auth`

</td>
<td>

Denies the request_auth command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`better-auth:allow-sign-out`

</td>
<td>

Enables the sign_out command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`better-auth:deny-sign-out`

</td>
<td>

Denies the sign_out command without any pre-configured scope.

</td>
</tr>
</table>
