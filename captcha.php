<?php
require __DIR__ . '/vendor/autoload.php';
use Gregwar\Captcha\CaptchaBuilder;

$builder = new CaptchaBuilder;
$builder->build();
?>
<html>
<body>
<img src="<?php echo $builder->inline(); ?>" />
</body>
</html>
<?php
if($builder->testPhrase($userInput)) {
	// instructions if user phrase is good
	echo 'true'
}
else {
	// user phrase is wrong
	echo 'false'
}
