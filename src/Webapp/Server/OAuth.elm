module Webapp.Server.OAuth exposing
    ( AccessTokenResponse
    , Config
    , FreshAccessToken
    , FreshAccessTokenResponse
    , GrantType(..)
    , accessToken
    , authorizationHeader
    , authorizeLink
    , decodeAccessTokenResponse
    , encodeAccessTokenResponse
    , freshAccessToken
    , freshAccessTokenResponse
    , router
    , updateFromRoute
    )

import Base64
import Http
import Json.Decode
import Json.Encode
import JsonWebToken
import Task exposing (Task)
import Time
import Url.Builder
import Url.Parser exposing ((</>), (<?>), map, s, string)
import Url.Parser.Query
import Webapp.Server.HTTP exposing (Response, StatusCode(..))


type alias Config =
    { authorizeUrl : String
    , accessTokenUrl : String
    , clientId : String
    , clientSecret : String
    , scopes : String
    , httpTimeout : Maybe Float
    , customHeaders : List ( String, String )
    , customParams : List ( String, String )
    }


updateFromRoute :
    { state : String
    , onSuccess : AccessTokenResponse -> Task Response Response
    , onFail : Http.Error -> Response
    , now : Time.Posix
    , redirectUrl : String
    }
    -> Config
    -> Result String (Maybe String)
    -> Task Response Response
updateFromRoute { state, onSuccess, onFail, now, redirectUrl } oauthConfig codeResult =
    case codeResult of
        Ok Nothing ->
            let
                targetUrl =
                    authorizeLink oauthConfig { state = state, redirectUrl = redirectUrl }
            in
            Task.succeed
                { statusCode = StatusSeeOther
                , body = "Go to " ++ targetUrl
                , headers =
                    [ ( "Location", Json.Encode.string targetUrl )
                    ]
                }

        Ok (Just code) ->
            let
                withFreshAccessToken tokenResponse =
                    freshAccessTokenResponse tokenResponse oauthConfig redirectUrl now
                        |> Task.map freshAccessToken
            in
            accessToken oauthConfig redirectUrl [] (GrantAuthorizationCode code)
                |> Task.mapError onFail
                |> Task.andThen onSuccess

        Err err ->
            Task.fail (onFail (Http.BadUrl err))


authorizeLink : Config -> { state : String, redirectUrl : String } -> String
authorizeLink { authorizeUrl, clientId, customParams, scopes } { state, redirectUrl } =
    authorizeUrl
        ++ Url.Builder.toQuery
            ([ Url.Builder.string "client_id" clientId
             , Url.Builder.string "scope" scopes
             , Url.Builder.string "redirect_uri" redirectUrl
             , Url.Builder.string "state" state
             ]
                ++ List.map (\( key, value ) -> Url.Builder.string key value) customParams
            )


type AccessToken
    = AccessToken String


decodeAccessToken : Json.Decode.Decoder AccessToken
decodeAccessToken =
    Json.Decode.string
        |> Json.Decode.map AccessToken


encodeAccessToken : AccessToken -> Json.Encode.Value
encodeAccessToken (AccessToken s) =
    Json.Encode.string s


authorizationHeader : FreshAccessToken -> Http.Header
authorizationHeader (FreshAccessToken s) =
    Http.header "Authorization" ("Bearer " ++ s)


type RefreshToken
    = RefreshToken String


decodeRefreshToken : Json.Decode.Decoder RefreshToken
decodeRefreshToken =
    Json.Decode.string
        |> Json.Decode.map RefreshToken


encodeRefreshToken : RefreshToken -> Json.Encode.Value
encodeRefreshToken (RefreshToken s) =
    Json.Encode.string s


type alias AccessTokenResponse =
    { accessToken : AccessToken
    , refreshToken : Maybe RefreshToken
    , raw : Json.Encode.Value
    }


decodeAccessTokenResponse : Json.Decode.Decoder AccessTokenResponse
decodeAccessTokenResponse =
    Json.Decode.map3 AccessTokenResponse
        (Json.Decode.field "access_token" Json.Decode.string |> Json.Decode.map AccessToken)
        (Json.Decode.maybe (Json.Decode.field "refresh_token" Json.Decode.string |> Json.Decode.map RefreshToken))
        Json.Decode.value


encodeAccessTokenResponse : AccessTokenResponse -> Json.Encode.Value
encodeAccessTokenResponse resp =
    let
        (AccessToken atoken) =
            resp.accessToken

        rtoken =
            case resp.refreshToken of
                Just (RefreshToken a) ->
                    [ ( "refreshToken", Json.Encode.string a ) ]

                _ ->
                    []
    in
    Json.Encode.object
        (( "accessToken", Json.Encode.string atoken ) :: rtoken)


type GrantType
    = GrantAuthorizationCode String
    | GrantRefreshToken RefreshToken


accessToken : Config -> String -> List Url.Builder.QueryParameter -> GrantType -> Task Http.Error AccessTokenResponse
accessToken { accessTokenUrl, clientId, clientSecret, httpTimeout, customHeaders, customParams } redirectUrl moreParams tokenRequest =
    let
        removePrefix prefix s =
            if String.startsWith prefix s then
                String.dropLeft (String.length prefix) s

            else
                s

        codeParams =
            case tokenRequest of
                GrantAuthorizationCode code ->
                    [ Url.Builder.string "code" code
                    , Url.Builder.string "grant_type" "authorization_code"
                    ]

                GrantRefreshToken (RefreshToken refreshToken) ->
                    [ Url.Builder.string "refresh_token" refreshToken
                    , Url.Builder.string "grant_type" "refresh_token"
                    ]

        bodyPayload =
            Url.Builder.toQuery
                ([ Url.Builder.string "client_id" clientId
                 , Url.Builder.string "client_secret" clientSecret
                 , Url.Builder.string "redirect_uri" redirectUrl
                 ]
                    ++ List.map (\( key, value ) -> Url.Builder.string key value) customParams
                    ++ codeParams
                    ++ moreParams
                )
                |> removePrefix "?"

        httpJsonBodyResolver : Json.Decode.Decoder a -> Http.Response String -> Result Http.Error a
        httpJsonBodyResolver decoder resp =
            case resp of
                Http.GoodStatus_ m s ->
                    Json.Decode.decodeString decoder s
                        |> Result.mapError (Json.Decode.errorToString >> Http.BadBody)

                Http.BadUrl_ s ->
                    Err (Http.BadUrl s)

                Http.Timeout_ ->
                    Err Http.Timeout

                Http.NetworkError_ ->
                    Err Http.NetworkError

                Http.BadStatus_ m s ->
                    Err (Http.BadStatus m.statusCode)
    in
    Http.task
        { method = "POST"
        , headers = List.map (\( k, v ) -> Http.header k v) customHeaders
        , url = accessTokenUrl
        , body = Http.stringBody "application/x-www-form-urlencoded" bodyPayload
        , resolver = Http.stringResolver (httpJsonBodyResolver decodeAccessTokenResponse)
        , timeout = httpTimeout
        }


{-| no verification here. just decoding the data.
useful for extracting `exp` to know if token had expired

extracted from JsonWebToken `decodePayload`

-}
decodePayloadWithoutVerification : Json.Decode.Decoder a -> AccessToken -> Result String a
decodePayloadWithoutVerification decoder (AccessToken string) =
    case String.split "." string of
        [ part0, part1, signVar ] ->
            part1
                |> Base64.decode
                |> Result.andThen (Json.Decode.decodeString decoder >> Result.mapError Json.Decode.errorToString)

        _ ->
            Err "Invalid token"


expiry : AccessToken -> Maybe Time.Posix
expiry token =
    let
        decoder =
            Json.Decode.field "exp" Json.Decode.int |> Json.Decode.map (\i -> Time.millisToPosix (i * 1000))
    in
    decodePayloadWithoutVerification decoder token
        |> Result.toMaybe


{-| Returns a wrapped `FreshAccessTokenResponse oauth` if already fresh, otherwise obtain a fresh one
-}
freshAccessTokenResponse : AccessTokenResponse -> Config -> String -> Time.Posix -> Task Http.Error FreshAccessTokenResponse
freshAccessTokenResponse oauth config redirectUrl now =
    let
        accessTokenExpiry =
            Maybe.withDefault now (expiry oauth.accessToken) |> Time.posixToMillis
    in
    case ( oauth.refreshToken, accessTokenExpiry > (Time.posixToMillis now + (600 * 1000)) ) of
        ( Just refreshToken, False ) ->
            accessToken config redirectUrl [] (GrantRefreshToken refreshToken)
                |> Task.map FreshAccessTokenResponse

        ( _, True ) ->
            Task.succeed (FreshAccessTokenResponse oauth)

        ( Nothing, False ) ->
            -- best effort attempt with existing access token
            Task.succeed (FreshAccessTokenResponse oauth)


type FreshAccessTokenResponse
    = FreshAccessTokenResponse AccessTokenResponse


{-| only obtained via freshAccessToken
-}
type FreshAccessToken
    = FreshAccessToken String


freshAccessToken : FreshAccessTokenResponse -> FreshAccessToken
freshAccessToken (FreshAccessTokenResponse resp) =
    let
        (AccessToken s) =
            resp.accessToken
    in
    FreshAccessToken s



-- Route


router : Url.Parser.Parser (a -> Maybe error -> value -> d) (String -> Maybe String -> Maybe String -> b) -> (a -> Result error value -> d) -> Url.Parser.Parser (b -> c) c
router prefix constructor =
    let
        fn provider maybeErr maybeCode =
            case maybeErr of
                Just x ->
                    constructor provider (Err x)

                Nothing ->
                    constructor provider (Ok maybeCode)
    in
    map fn (prefix </> Url.Parser.string <?> Url.Parser.Query.string "error" <?> Url.Parser.Query.string "code")
