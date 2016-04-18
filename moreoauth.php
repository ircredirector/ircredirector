<?php
require 'vendor/autoload.php';
use MediaWiki\OAuthClient\ClientConfig;
use MediaWiki\OAuthClient\Consumer;
use MediaWiki\OAuthClient\Client;

$endpoint = 'https://en.wikipedia.org/w/index.php?title=Special:OAuth';
$redir = 'https://en.wikipedia.org/wiki/Special:OAuth?';
$consumerKey = file_get_contents('../oauthinis/key');
$consumerSecret = file_get_contents('../oauthinis/secret');

$conf = new ClientConfig( $endpoint );
$conf->setRedirURL( $redir );
$conf->setConsumer( new Consumer( $consumerKey, $consumerSecret ) );

$client = new Client( $conf );
//$client->setCallback('oob');

// Step 1 = Get a request token
list( $next, $token ) = $client->initiate();

// Step 2 - Have the user authorize your app. Get a verifier code from
// them. (if this was a webapp, you would redirect your user to $next,
// then use the 'oauth_verifier' GET parameter when the user is redirected
// back to the callback url you registered.
echo "Point your browser to: $next\n\n";
print "Enter the verification code:\n";
$fh = fopen( 'php://stdin', 'r' );
$verifyCode = trim( fgets( $fh ) );

// Step 3 - Exchange the token and verification code for an access
// token
$accessToken = $client->complete( $token,  $verifyCode );

// You're done! You can now identify the user, and/or call the API with
// $accessToken

// If we want to authenticate the user
$ident = $client->identify( $accessToken );
echo "Authenticated user {$ident->username}\n";

// Do a simple API call
//echo "Getting user info: ";
//echo $client->makeOAuthCall(
//    $accessToken,
//    'https://localhost/wiki/api.php?action=query&meta=userinfo&uiprop=rights&format=json'
//);

// Make an Edit
//$editToken = json_decode( $client->makeOAuthCall(
//    $accessToken,
//    'https://localhost/wiki/api.php?action=tokens&format=json'
//) )->tokens->edittoken;

//$apiParams = array(
//    'action' => 'edit',
//    'title' => 'Talk:Main_Page',
//    'section' => 'new',
//    'summary' => 'Hello World',
//    'text' => 'Hi',
//    'token' => $editToken,
//   'format' => 'json',
//);

//$client->setExtraParams( $apiParams ); // sign these too

//echo $client->makeOAuthCall(
//    $accessToken,
//    'https://localhost/wiki/api.php',
//    true,
//    $apiParams
//);
?>
