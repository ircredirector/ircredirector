<?php
/**
 * Written in 2013 by Brad Jorsch
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * See <http://creativecommons.org/publicdomain/zero/1.0/> for a copy of the
 * CC0 Public Domain Dedication.
 */

// ******************** CONFIGURATION ********************

/**
 * Set this to point to a file (outside the webserver root!) containing the
 * following keys:
 * - agent: The HTTP User-Agent to use
 * - consumerKey: The "consumer token" given to you when registering your app
 * - consumerSecret: The "secret token" given to you when registering your app
 */
$inifile = '/data/project/ircredirector/oauth.ini';

/**
 * Set this to the Special:OAuth/authorize URL.
 * To work around MobileFrontend redirection, use /wiki/ rather than /w/index.php.
 */
$mwOAuthAuthorizeUrl = 'https://www.mediawiki.org/wiki/Special:OAuth/authorize';

/**
 * Set this to the Special:OAuth URL.
 * Note that /wiki/Special:OAuth fails when checking the signature, while
 * index.php?title=Special:OAuth works fine.
 */
$mwOAuthUrl = 'https://www.mediawiki.org/w/index.php?title=Special:OAuth';

/**
 * Set this to the interwiki prefix for the OAuth central wiki.
 */
$mwOAuthIW = 'mw';

/**
 * Set this to the API endpoint
 */
$apiUrl = 'https://test.wikipedia.org/w/api.php';

/**
 * Set this to Special:MyTalk on the above wiki
 */
$mytalkUrl = 'https://test.wikipedia.org/wiki/Special:MyTalk';

// ****************** END CONFIGURATION ******************

// Setup the session cookie
session_name( 'OAuthHelloWorldEnduser' );
$params = session_get_cookie_params();
session_set_cookie_params(
    $params['lifetime'],
    dirname( $_SERVER['SCRIPT_NAME'] )
);


// Read the ini file
$ini = parse_ini_file( $inifile );
if ( $ini === false ) {
    header( "HTTP/1.1 500 Internal Server Error" );
    echo 'The ini file could not be read';
    exit(0);
}
if ( !isset( $ini['agent'] ) ||
    !isset( $ini['consumerKey'] ) ||
    !isset( $ini['consumerSecret'] )
) {
    header( "HTTP/1.1 500 Internal Server Error" );
    echo 'Required configuration directives not found in ini file';
    exit(0);
}
$gUserAgent = $ini['agent'];
$gConsumerKey = $ini['consumerKey'];
$gConsumerSecret = $ini['consumerSecret'];

// Load the user token (request or access) from the session
$gTokenKey = '';
$gTokenSecret = '';
session_start();
if ( isset( $_SESSION['tokenKey'] ) ) {
    $gTokenKey = $_SESSION['tokenKey'];
    $gTokenSecret = $_SESSION['tokenSecret'];
}
session_write_close();

// Fetch the access token if this is the callback from requesting authorization
if ( isset( $_GET['oauth_verifier'] ) && $_GET['oauth_verifier'] ) {
    fetchAccessToken();
    doEdit();
}

// Take any requested action
switch ( isset( $_GET['action'] ) ? $_GET['action'] : '' ) {
    case 'download':
        header( 'Content-Type: text/plain' );
        readfile( __FILE__ );
        return;

    case 'edit':
        doEdit();
        break;
}


// ******************** CODE ********************


/**
 * Utility function to sign a request
 *
 * Note this doesn't properly handle the case where a parameter is set both in
 * the query string in $url and in $params, or non-scalar values in $params.
 *
 * @param string $method Generally "GET" or "POST"
 * @param string $url URL string
 * @param array $params Extra parameters for the Authorization header or post
 * 	data (if application/x-www-form-urlencoded).
 *Â @return string Signature
 */
function sign_request( $method, $url, $params = array() ) {
    global $gConsumerSecret, $gTokenSecret;

    $parts = parse_url( $url );

    // We need to normalize the endpoint URL
    $scheme = isset( $parts['scheme'] ) ? $parts['scheme'] : 'http';
    $host = isset( $parts['host'] ) ? $parts['host'] : '';
    $port = isset( $parts['port'] ) ? $parts['port'] : ( $scheme == 'https' ? '443' : '80' );
    $path = isset( $parts['path'] ) ? $parts['path'] : '';
    if ( ( $scheme == 'https' && $port != '443' ) ||
        ( $scheme == 'http' && $port != '80' )
    ) {
        // Only include the port if it's not the default
        $host = "$host:$port";
    }

    // Also the parameters
    $pairs = array();
    parse_str( isset( $parts['query'] ) ? $parts['query'] : '', $query );
    $query += $params;
    unset( $query['oauth_signature'] );
    if ( $query ) {
        $query = array_combine(
        // rawurlencode follows RFC 3986 since PHP 5.3
            array_map( 'rawurlencode', array_keys( $query ) ),
            array_map( 'rawurlencode', array_values( $query ) )
        );
        ksort( $query, SORT_STRING );
        foreach ( $query as $k => $v ) {
            $pairs[] = "$k=$v";
        }
    }

    $toSign = rawurlencode( strtoupper( $method ) ) . '&' .
        rawurlencode( "$scheme://$host$path" ) . '&' .
        rawurlencode( join( '&', $pairs ) );
    $key = rawurlencode( $gConsumerSecret ) . '&' . rawurlencode( $gTokenSecret );
    return base64_encode( hash_hmac( 'sha1', $toSign, $key, true ) );
}

/**
 * Request authorization
 * @return void
 */
function doAuthorizationRedirect() {
    global $mwOAuthUrl, $mwOAuthAuthorizeUrl, $gUserAgent, $gConsumerKey, $gTokenSecret;

    // First, we need to fetch a request token.
    // The request is signed with an empty token secret and no token key.
    $gTokenSecret = '';
    $url = $mwOAuthUrl . '/initiate';
    $url .= strpos( $url, '?' ) ? '&' : '?';
    $url .= http_build_query( array(
        'format' => 'json',

        // OAuth information
        'oauth_callback' => 'http://tools.wmflabs.org/ircredirector/index4.php', // Must be "oob" for MWOAuth
        'oauth_consumer_key' => $gConsumerKey,
        'oauth_version' => '1.0',
        'oauth_nonce' => md5( microtime() . mt_rand() ),
        'oauth_timestamp' => time(),

        // We're using secret key signatures here.
        'oauth_signature_method' => 'HMAC-SHA1',
    ) );
    $signature = sign_request( 'GET', $url );
    $url .= "&oauth_signature=" . urlencode( $signature );
    $ch = curl_init();
    curl_setopt( $ch, CURLOPT_URL, $url );
    //curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
    curl_setopt( $ch, CURLOPT_USERAGENT, $gUserAgent );
    curl_setopt( $ch, CURLOPT_HEADER, 0 );
    curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1 );
    $data = curl_exec( $ch );
    if ( !$data ) {
        header( "HTTP/1.1 500 Internal Server Error" );
        echo "<p>There was an error communicating with the wiki for app authorization. Please try again.</p>\n";
        echo '<!-- Curl error: ' . htmlspecialchars( curl_error( $ch ) ) . ' -->';
        exit(0);
    }
    curl_close( $ch );
    $token = json_decode( $data );
    if ( is_object( $token ) && isset( $token->error ) ) {
        header( "HTTP/1.1 500 Internal Server Error" );
        echo "<p>There was an error communicating with the wiki for app authorization. Please try again.</p>\n";
        echo '<!-- Error retrieving token: ' . htmlspecialchars( $token->error ) . ' -->';
        exit(0);
    }
    if ( !is_object( $token ) || !isset( $token->key ) || !isset( $token->secret ) ) {
        header( "HTTP/1.1 500 Internal Server Error" );
        echo "<p>There was an error communicating with the wiki for app authorization. Please try again.</p>\n";
        echo '<!-- Invalid response from token request -->';
        exit(0);
    }

    // Now we have the request token, we need to save it for later.
    session_start();
    $_SESSION['tokenKey'] = $token->key;
    $_SESSION['tokenSecret'] = $token->secret;
    session_write_close();

    // Then we send the user off to authorize
    $url = $mwOAuthAuthorizeUrl;
    $url .= strpos( $url, '?' ) ? '&' : '?';
    $url .= http_build_query( array(
        'oauth_token' => $token->key,
        'oauth_consumer_key' => $gConsumerKey,
    ) );
    header( "Location: $url" );
    echo 'Please see <a href="' . htmlspecialchars( $url ) . '">' . htmlspecialchars( $url ) . '</a>';
}

/**
 * Handle a callback to fetch the access token
 * @return void
 */
function fetchAccessToken() {
    global $mwOAuthUrl, $gUserAgent, $gConsumerKey, $gTokenKey, $gTokenSecret;

    $url = $mwOAuthUrl . '/token';
    $url .= strpos( $url, '?' ) ? '&' : '?';
    $url .= http_build_query( array(
        'format' => 'json',
        'oauth_verifier' => $_GET['oauth_verifier'],

        // OAuth information
        'oauth_consumer_key' => $gConsumerKey,
        'oauth_token' => $gTokenKey,
        'oauth_version' => '1.0',
        'oauth_nonce' => md5( microtime() . mt_rand() ),
        'oauth_timestamp' => time(),

        // We're using secret key signatures here.
        'oauth_signature_method' => 'HMAC-SHA1',
    ) );
    $signature = sign_request( 'GET', $url );
    $url .= "&oauth_signature=" . urlencode( $signature );
    $ch = curl_init();
    curl_setopt( $ch, CURLOPT_URL, $url );
    //curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
    curl_setopt( $ch, CURLOPT_USERAGENT, $gUserAgent );
    curl_setopt( $ch, CURLOPT_HEADER, 0 );
    curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1 );
    $data = curl_exec( $ch );
    if ( !$data ) {
        header( "HTTP/1.1 500 Internal Server Error" );
        echo "<p>There was an error communicating with the wiki for app authorization. Please try again.</p>\n";
        echo '<!-- Curl error: ' . htmlspecialchars( curl_error( $ch ) ) . ' -->';
        exit(0);
    }
    curl_close( $ch );
    $token = json_decode( $data );
    if ( is_object( $token ) && isset( $token->error ) ) {
        header( "HTTP/1.1 500 Internal Server Error" );
        echo "<p>There was an error communicating with the wiki for app authorization. Please try again.</p>\n";
        echo '<!-- Error retrieving token: ' . htmlspecialchars( $token->error ) . ' -->';
        exit(0);
    }
    if ( !is_object( $token ) || !isset( $token->key ) || !isset( $token->secret ) ) {
        header( "HTTP/1.1 500 Internal Server Error" );
        echo "<p>There was an error communicating with the wiki for app authorization. Please try again.</p>\n";
        echo '<!-- Invalid response from token request -->';
        exit(0);
    }

    // Save the access token
    session_start();
    $_SESSION['tokenKey'] = $gTokenKey = $token->key;
    $_SESSION['tokenSecret'] = $gTokenSecret = $token->secret;
    session_write_close();
}


/**
 * Send an API query with OAuth authorization
 *
 * @param array $post Post data
 * @param object $ch Curl handle
 * @return array API results
 */
function doApiQuery( $post, &$ch = null ) {
    global $apiUrl, $gUserAgent, $gConsumerKey, $gTokenKey;

    $headerArr = array(
        // OAuth information
        'oauth_consumer_key' => $gConsumerKey,
        'oauth_token' => $gTokenKey,
        'oauth_version' => '1.0',
        'oauth_nonce' => md5( microtime() . mt_rand() ),
        'oauth_timestamp' => time(),

        // We're using secret key signatures here.
        'oauth_signature_method' => 'HMAC-SHA1',
    );
    $signature = sign_request( 'POST', $apiUrl, $post + $headerArr );
    $headerArr['oauth_signature'] = $signature;

    $header = array();
    foreach ( $headerArr as $k => $v ) {
        $header[] = rawurlencode( $k ) . '="' . rawurlencode( $v ) . '"';
    }
    $header = 'Authorization: OAuth ' . join( ', ', $header );

    if ( !$ch ) {
        $ch = curl_init();
    }
    curl_setopt( $ch, CURLOPT_POST, true );
    curl_setopt( $ch, CURLOPT_URL, $apiUrl );
    curl_setopt( $ch, CURLOPT_POSTFIELDS, http_build_query( $post ) );
    curl_setopt( $ch, CURLOPT_HTTPHEADER, array( $header ) );
    //curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
    curl_setopt( $ch, CURLOPT_USERAGENT, $gUserAgent );
    curl_setopt( $ch, CURLOPT_HEADER, 0 );
    curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1 );
    $data = curl_exec( $ch );
    if ( !$data ) {
        header( "HTTP/1.1 500 Internal Server Error" );
        echo "<p>There was an error communicating with the wiki when performing the edit. Please try again.</p>\n";
        echo '<!-- Curl error: ' . htmlspecialchars( curl_error( $ch ) ) . ' -->';
        exit(0);
    }
    $ret = json_decode( $data );
    if ( !$data ) {
        header( "HTTP/1.1 500 Internal Server Error" );
        echo "<p>There was an error communicating with the wiki when performing the edit. Please try again.</p>\n";
        echo '<!-- JSON decode failed: ' . htmlspecialchars( $data ) . ' -->';
        exit(0);
    }
    return $ret;
}

/**
 * Perform a generic edit
 * @return void Does not return
 */
function doEdit() {
    global $mwOAuthIW;

    $ch = null;

    // First fetch the username
    $res = doApiQuery( array(
        'format' => 'json',
        'action' => 'query',
        'meta' => 'userinfo',
    ), $ch );

    if ( isset( $res->error->code ) && $res->error->code === 'mwoauth-invalid-authorization' ) {
        // We're not authorized!
        doAuthorizationRedirect();
        return;
    }

    if ( !isset( $res->query->userinfo ) ) {
        header( "HTTP/1.1 500 Internal Server Error" );
        echo "<p>There was an error communicating with the wiki when performing the edit. Please try again.</p>\n";
        echo '<!-- Bad API response: ' . htmlspecialchars( var_export( $res, 1 ) ) . ' -->';
        exit(0);
    }
    if ( isset( $res->query->userinfo->anon ) ) {
        header( "HTTP/1.1 500 Internal Server Error" );
        echo "<p>There was an error communicating with the wiki when performing the edit. Please try again.</p>\n";
        echo '<!-- Not logged in. (How did that happen?) -->';
        exit(0);
    }
    $page = 'User talk:' . $res->query->userinfo->name;

    // Next fetch the edit token
    $res = doApiQuery( array(
        'format' => 'json',
        'action' => 'tokens',
        'type' => 'edit',
    ), $ch );
    if ( !isset( $res->tokens->edittoken ) ) {
        header( "HTTP/1.1 500 Internal Server Error" );
        echo "<p>There was an error communicating with the wiki when performing the edit. Please try again.</p>\n";
        echo '<!-- Bad API response: ' . htmlspecialchars( var_export( $res, 1 ) ) . ' -->';
        exit(0);
    }
    $token = $res->tokens->edittoken;

    // Now perform the edit
    $res = doApiQuery( array(
        'format' => 'json',
        'action' => 'edit',
        'title' => $page,
        'section' => 'new',
        'sectiontitle' => 'Hello, end user',
        'text' => 'This message was posted using the OAuth Hello World end-user application, and should be seen as coming from yourself. To revoke this application\'s access to your account, visit [[:' . $mwOAuthIW . ':Special:OAuthManageMyGrants]]. ~~~~',
        'summary' => '/* Hello, world */ Hello from OAuth!',
        'watchlist' => 'nochange',
        'token' => $token,
    ), $ch );

    if ( !isset( $res->edit->result ) || $res->edit->result !== 'Success' ) {
        header( "HTTP/1.1 500 Internal Server Error" );
        echo "<p>There was an error communicating with the wiki when performing the edit. Please try again.</p>\n";
        echo '<!-- Edit failed: ' . htmlspecialchars( var_export( $res, 1 ) ) . ' -->';
        exit(0);
    }

    global $mytalkUrl;
    $url = $mytalkUrl;
    $url .= strpos( $url, '?' ) ? '&' : '?';
    $url .= http_build_query( array(
        'diff' => $res->edit->newrevid,
        'oldid' => $res->edit->oldrevid,
        'oldid' => $gConsumerKey,
    ) );
    header( "Location: $url" );
    echo 'Please see <a href="' . htmlspecialchars( $url ) . '">' . htmlspecialchars( $url ) . '</a>';
}

// ******************** WEBPAGE ********************

?><!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8" />
    <title>OAuth Hello World!</title>
</head>
<body>
<h2>Edit your talk page using OAuth</h2>
<p>This is a very simple "<a href="//en.wikipedia.org/wiki/Hello_world_program">Hello world</a>" program to show how OAuth works for end users. If you so desire, you may <a href="<?php echo htmlspecialchars( $_SERVER['SCRIPT_NAME'] );?>?action=download">download this file</a>. If you're a developer, you might be interested in <a href="index.php">this other version</a>.</p>
<form method="get" action="<?php echo htmlspecialchars( $_SERVER['SCRIPT_NAME'] );?>">
    <input type="hidden" name="action" value="edit">
    <input type="submit" value="Make an edit!">
</form>
<hr>
<h3>So what is this doing?</h3>
<ol>
    <li>You click "Make an edit!"</li>
    <li>This app requests a temporary token from mediawiki.org, then sends your browser to a page on mediawiki.org to authorize this application.</li>
    <li>You login to mediawiki.org (if you aren't already). Then you'll be prompted to give this application certain "grants"â€”actions that the application is allowed to take on your behalf. This application just asks to be able to create and edit pages, so it can post to your talk page (and create your talk page, if it doesn't already exist).</li>
    <li>Once you allow this application to act on your behalf, your browser is redirected back to our application with a verification code. This application uses that verification code and the temporary token from step 2 to get an authorization token.</li>
    <li>The app uses the authorization token to post to your talk page on test.wikipedia.org from your user account. Then it redirects you to the resulting diff.</li>
    <li>If all goes well, you see the diff that this application made and that it was done from your user account!</li>
</ol>
If you come back and click "Make an edit!" again before the browser session expires, the application will remember the authorization token and skip straight to step 5. And if you happen to have gone to <a href="https://www.mediawiki.org/wiki/Special:OAuthManageMyGrants">Special:OAuthManageMyGrants on mediawiki.org</a> and revoked the access token in the mean time, it will receive an error when it tries to edit and will automatically go to step 2.


</body>
</html>
