import requrl from 'requrl'
import type {
  EndpointsOption,
  SchemeOptions,
  SchemePartialOptions,
  TokenableScheme,
  TokenableSchemeOptions,
  RefreshableSchemeOptions,
  UserOptions,
  HTTPResponse,
  SchemeCheck
} from '../types'
import type { Auth } from '../core'
import {
  encodeQuery,
  getProp,
  randomString,
  normalizePath,
  urlJoin,
  parseQuery,
  removeTokenPrefix,
} from '../utils'
import {
  Token,
  RequestHandler,
  RefreshToken,
  RefreshController,
  ExpiredAuthSessionError
} from '../inc'
import { BaseScheme } from './base'
import {
  PublicClientApplication,
  LogLevel,
  ProtocolMode,
  AuthorizationUrlRequest,
  AuthorizationCodeRequest,
  AuthenticationResult,
  AccountInfo
} from '@azure/msal-node'
import { debug } from 'console'

export interface MsalSchemeEndpoints extends EndpointsOption {
  authorization: string
  token: string
  userInfo: string
  logout: string
}

export interface MsalSchemeOptions
  extends SchemeOptions,
  TokenableSchemeOptions,
  RefreshableSchemeOptions {
  endpoints: MsalSchemeEndpoints
  user: UserOptions
  responseType: 'code' | 'token' | 'id_token' | 'none' | string
  clientId: string
  authority: string
  clientSecret: string
  grantType: string | false
  redirectUri: string
  logoutRedirectUri: string
  scope: string[]
  state: string
  codeChallengeMethod: 'implicit' | 'S256' | 'plain'
  audience: string
  knownAuthorities: string[]
  autoLogout: boolean
}

const DEFAULTS: SchemePartialOptions<MsalSchemeOptions> = {
  name: 'msal',
  clientId: null,
  authority: null,
  clientSecret: null,
  redirectUri: null,
  logoutRedirectUri: null,
  state: null,
  codeChallengeMethod: 'S256',
  audience: null,
  scope: [],
  user: {
    property: false
  },
  endpoints: {
    logout: '',
    authorization: '',
    token: '',
    userInfo: ''
  },
  token: {
    property: 'access_token',
    type: 'Bearer',
    name: 'Authorization',
    maxAge: 1800,
    global: true,
    prefix: '_token.',
    expirationPrefix: '_token_expiration.'
  },
  refreshToken: {
    property: 'refresh_token',
    maxAge: 60 * 60 * 24 * 30,
    prefix: '_refresh_token.',
    expirationPrefix: '_refresh_token_expiration.'
  },
  responseType: 'token',
  autoLogout: false,
}

export class MsalScheme<
  OptionsT extends MsalSchemeOptions = MsalSchemeOptions
  >
  extends BaseScheme<OptionsT>
  implements TokenableScheme<OptionsT> {
  public token: Token
  public requestHandler: RequestHandler
  public msal: PublicClientApplication
  public refreshToken: RefreshToken
  public refreshController: RefreshController

  constructor(
    $auth: Auth,
    options: SchemePartialOptions<MsalSchemeOptions>,
    ...defaults: SchemePartialOptions<MsalSchemeOptions>[]
  ) {
    super(
      $auth,
      options as OptionsT,
      ...(defaults as OptionsT[]),
      DEFAULTS as OptionsT
    )

    // Initialize Token instance
    this.token = new Token(this, this.$auth.$storage)

    // Initialize Request Interceptor
    this.requestHandler = new RequestHandler(this, this.$auth.ctx.$axios)

    const config = {
      auth: {
        clientId: options.clientId,
        authority: options.authority,
        knownAuthorities: options.knownAuthorities,
      },
      cache: {
        cacheLocation: 'localStorage',
      },
      // cache: {
      //   cachePlugin: {
      //     beforeCacheAccess: async (cacheContext: any) => {
      //       return new Promise<void>(async (resolve, reject) => {
      //         const data = this.$auth.$storage.getUniversal(this.name + '.token_cache')
      //         if (data){
      //           console.log('beforeCacheAccess - read', data)
      //           cacheContext.tokenCache.deserialize(data)
      //           resolve()
      //         } else {
      //           console.log('beforeCacheAccess - write')
      //           const writeData = JSON.stringify(cacheContext.tokenCache.serialize())
      //           this.$auth.$storage.setUniversal(this.name + '.token_cache',
      //             writeData
      //           )
      //         }
      //       }); 
      //     },
      //     afterCacheAccess: async (cacheContext: any) => { 
      //       if (cacheContext.cacheHasChanged) {
      //         console.log('afterCacheAccess - write')
      //         const writeData = JSON.stringify(cacheContext.tokenCache.serialize())
      //         this.$auth.$storage.setUniversal(this.name + '.token_cache',
      //           writeData
      //         )
      //       } 
      //     }
      //   }
      // },
      system: {
        loggerOptions: {
          loggerCallback(loglevel, message, containsPii) {
            console.log(message);
          },
          piiLoggingEnabled: false,
          logLevel: LogLevel.Verbose,
        }
      }
    }
    this.msal = new PublicClientApplication(config)
  }

  protected get scope(): string {
    return Array.isArray(this.options.scope)
      ? this.options.scope.join(' ')
      : this.options.scope
  }

  protected get redirectURI(): string {
    const basePath = this.$auth.ctx.base || ''
    const path = normalizePath(
      basePath + '/' + this.$auth.options.redirect.callback
    ) // Don't pass in context since we want the base path
    return this.options.redirectUri || urlJoin(requrl(this.$auth.ctx.req), path)
  }

  protected get logoutRedirectURI(): string {
    return (
      this.options.logoutRedirectUri ||
      urlJoin(requrl(this.$auth.ctx.req), this.$auth.options.redirect.logout)
    )
  }

  check(checkStatus = false): SchemeCheck {
    const response = {
      valid: false,
      tokenExpired: false
    }

    // Sync token
    const token = this.token.sync()

    // Token is required but not available
    if (!token) {
      return response
    }

    // Check status wasn't enabled, let it pass
    if (!checkStatus) {
      response.valid = true
      return response
    }

    // Get status
    const tokenStatus = this.token.status()

    // Token has expired. Attempt `tokenCallback`
    if (tokenStatus.expired()) {
      response.tokenExpired = true
      return response
    }

    response.valid = true
    return response
  }

  async mounted(): Promise<HTTPResponse | void> {
    const { tokenExpired, refreshTokenExpired } = this.check(true)

    // Force reset if refresh token has expired
    // Or if `autoLogout` is enabled and token has expired
    if (refreshTokenExpired || (tokenExpired && this.options.autoLogout)) {
      this.$auth.reset()
    }

    // Initialize request interceptor
    this.requestHandler.initializeRequestInterceptor(
      this.options.endpoints.token
    )

    // Handle callbacks on page load
    const redirected = await this._handleCallback()

    if (!redirected) {
      return this.$auth.fetchUserOnce()
    }
  }

  reset(): void {
    this.$auth.setUser(false)
    this.token.reset()
    // this.refreshToken.reset()
    this.requestHandler.reset()
  }

  async login(
    _opts: { state?: string; params?; nonce?: string } = {}
  ): Promise<void> {
    const opts = {
      client_id: this.options.clientId,
      redirect_uri: this.redirectURI,
      scope: this.scope,
      // Note: The primary reason for using the state parameter is to mitigate CSRF attacks.
      // https://auth0.com/docs/protocols/oauth2/oauth-state
      state: _opts.state || randomString(10),
      code_challenge_method: this.options.codeChallengeMethod,
      ..._opts.params
    }

    if (opts.code_challenge_method) {
      switch (opts.code_challenge_method) {
        case 'plain':
        case 'S256':
          {
            const state = this.generateRandomString()
            this.$auth.$storage.setUniversal(this.name + '.pkce_state', state)
            const codeVerifier = this.generateRandomString()
            this.$auth.$storage.setUniversal(
              this.name + '.pkce_code_verifier',
              codeVerifier
            )
            const codeChallenge = await this.pkceChallengeFromVerifier(
              codeVerifier,
              opts.code_challenge_method === 'S256'
            )
            opts.code_challenge = window.encodeURIComponent(codeChallenge)
          }
          break
        case 'implicit':
        default:
          break
      }
    }

    this.$auth.$storage.setUniversal(this.name + '.state', opts.state)

    const loginRequest: AuthorizationUrlRequest =
    {
      redirectUri: opts.redirect_uri,
      codeChallenge: opts.code_challenge, // PKCE Code Challenge
      codeChallengeMethod: opts.code_challenge_method, // PKCE Code Challenge Method

      authority: this.options.authority,
      scopes: this.options.scope,
      state: opts.state,
    }

    let url = await this.msal.getAuthCodeUrl(loginRequest)

    url = url.replace('openid%20profile%20offline_access', encodeURI(this.scope))

    window.location.replace(url)
  }

  logout(): void {
    if (this.options.endpoints.logout) {
      const opts = {
        client_id: this.options.clientId + '',
        logout_uri: this.logoutRedirectURI
      }
      const url = this.options.endpoints.logout + '?' + encodeQuery(opts)
      window.location.replace(url)
    }
    return this.$auth.reset()
  }

  async fetchUser(): Promise<void> {
    if (!this.check().valid) {
      return
    }

    const account = this.$auth.$storage.getUniversal(
      this.name + '.account'
    )

    if (!account) {
      this.$auth.setUser({})
      return
    }
    this.$auth.setUser((account as AccountInfo).idTokenClaims)

    try {
      let token = await this.msal.acquireTokenSilent({
        account: account as AccountInfo,
        scopes: this.options.scope,
      })

      this.$auth.setUser(token.account.idTokenClaims)
    } catch (error) {
      console.error(error)
    }
  }

  async _handleCallback(): Promise<boolean | void> {
    // Handle callback only for specified route
    if (
      this.$auth.options.redirect &&
      normalizePath(this.$auth.ctx.route.path, this.$auth.ctx) !==
      normalizePath(this.$auth.options.redirect.callback, this.$auth.ctx)
    ) {
      return
    }
    // Callback flow is not supported in server side
    if (process.server) {
      return
    }

    const hash = parseQuery(this.$auth.ctx.route.hash.substr(1))
    const parsedQuery = Object.assign({}, this.$auth.ctx.route.query, hash)
    // accessToken/idToken
    let token: string = parsedQuery[this.options.token.property] as string
    // refresh token
    let refreshToken: string

    if (this.options.refreshToken.property) {
      refreshToken = parsedQuery[this.options.refreshToken.property] as string
    }

    // Validate state
    const state = this.$auth.$storage.getUniversal(this.name + '.state')
    this.$auth.$storage.setUniversal(this.name + '.state', null)

    if (state && parsedQuery.state !== state) {
      return
    }

    // -- Authorization Code Grant --
    if (this.options.responseType === 'code' && parsedQuery.code) {
      let codeVerifier

      // Retrieve code verifier and remove it from storage
      if (
        this.options.codeChallengeMethod &&
        this.options.codeChallengeMethod !== 'implicit'
      ) {
        codeVerifier = this.$auth.$storage.getUniversal(
          this.name + '.pkce_code_verifier'
        )
        this.$auth.$storage.setUniversal(
          this.name + '.pkce_code_verifier',
          null
        )
      }

      const tokenRequest: AuthorizationCodeRequest =
      {
        authority: this.options.authority,
        scopes: this.options.scope,
        code: parsedQuery.code as string,
        codeVerifier: codeVerifier,
        redirectUri: this.redirectURI
      }

      try {
        console.log('acquireTokenByCode')
        const authenticationResult = await this.msal.acquireTokenByCode(tokenRequest)

        token = authenticationResult.accessToken
        console.log('token', token)

        this.$auth.$storage.setUniversal(
          this.name + '.account',
          authenticationResult.account
        )
        console.log(this.name + '.account', authenticationResult.account)
      }
      catch (error) {
        console.error(error)
      }
    }

    if (!token || !token.length) {
      return
    }

    // Set token
    this.token.set(token)

    // Store refresh token
    if (refreshToken && refreshToken.length) {
      this.refreshToken.set(refreshToken)
    }

    // Redirect to home
    this.$auth.redirect('home', true)

    return true // True means a redirect happened
  }

  async refreshTokens(): Promise<HTTPResponse | void> {
    // Get refresh token
    const refreshToken = this.refreshToken.get()

    // Refresh token is required but not available
    if (!refreshToken) {
      return
    }

    // Get refresh token status
    const refreshTokenStatus = this.refreshToken.status()

    // Refresh token is expired. There is no way to refresh. Force reset.
    if (refreshTokenStatus.expired()) {
      this.$auth.reset()

      throw new ExpiredAuthSessionError()
    }

    // Delete current token from the request header before refreshing
    this.requestHandler.clearHeader()

    const response = await this.$auth
      .request({
        method: 'post',
        url: this.options.endpoints.token,
        baseURL: '',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        data: encodeQuery({
          refresh_token: removeTokenPrefix(
            refreshToken,
            this.options.token.type
          ),
          client_id: this.options.clientId + '',
          grant_type: 'refresh_token'
        })
      })
      .catch((error) => {
        this.$auth.callOnError(error, { method: 'refreshToken' })
        return Promise.reject(error)
      })

    this.updateTokens(response)

    return response
  }

  protected updateTokens(response: HTTPResponse): void {
    const token = this.options.token.required
      ? (getProp(response.data, this.options.token.property) as string)
      : true

    this.token.set(token)
  }

  protected initializeRequestInterceptor(): void {
    this.requestHandler.initializeRequestInterceptor()
  }

  protected generateRandomString(): string {
    const array = new Uint32Array(28) // this is of minimum required length for servers with PKCE-enabled
    window.crypto.getRandomValues(array)
    return Array.from(array, (dec) => ('0' + dec.toString(16)).substr(-2)).join(
      ''
    )
  }

  protected async pkceChallengeFromVerifier(
    v: string,
    hashValue: boolean
  ): Promise<string> {
    if (hashValue) {
      const hashed = await this._sha256(v)
      return this._base64UrlEncode(hashed)
    }
    return v // plain is plain - url-encoded by default
  }

  private _sha256(plain: string): Promise<ArrayBuffer> {
    const encoder = new TextEncoder()
    const data = encoder.encode(plain)
    return window.crypto.subtle.digest('SHA-256', data)
  }

  private _base64UrlEncode(str: ArrayBuffer): string {
    // Convert the ArrayBuffer to string using Uint8 array to convert to what btoa accepts.
    // btoa accepts chars only within ascii 0-255 and base64 encodes them.
    // Then convert the base64 encoded to base64url encoded
    //   (replace + with -, replace / with _, trim trailing =)
    return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')
  }
}
