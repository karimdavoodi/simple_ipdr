<?php 
$PIN = "65878999902329";
if(isset($_GET["ok"])){
	$ip = $_SERVER['REMOTE_ADDR'];
	$p = $_GET["pin"];
	$d = $_GET["date"]; // 2018-01-09
	$t = $_GET["time"]; // 09:07
	if($p=="" || $d == "" || $t == ""){
		echo "Error 101";
		exit(0);
	}
	if(strstr($d,"-")==FALSe || strstr($t,":")==FALSE){
		echo "Error 102";
		exit(0);
	}
	if($p != $PIN ){
		echo "Error 103";
		sleep(3);
		exit(0);
	}
	$tok = explode("-",$d);
	if(count($tok)>2){
		$d = $tok[0].$tok[1].$tok[2];
	}
	if(file_exists("/home/ipdr/$d")){
		$list = glob("/home/ipdr/$d/*");
		$tok = explode(":",$t);
		$h = intval($tok[0]);
		$m = intval($tok[1]);
		$found = "";
		for($i=0; $i<10; $i++){
			$x = sprintf("%s%02d%02d",$d,$h,$m);
			foreach($list as $f){
				if(strstr($f,$x)!==FALSE){
					$found = $f;
					break;
				}
			}
			if($found !== "") break;
			$m -= 1;
			if($m == -1){ $m = 59; $h -= 1;}
			if($h == -1)  $h = 23;
		} 
		if($found != ""){
			$t = explode("/",$found);
			$n = $t[count($t)-1];
			header("Content-Type: application/x-gzip");
			header("Content-Disposition: attachment;filename=$n");
			$fp = fopen($found,"r");
			if($fp !== FALSE){
				while(!feof($fp)){
					$b = fread($fp,1024);
					if($b !== FALSE ) echo $b;
				}
			}
			exit(0);
		}else{
			echo "FILE NOT FOUND";
			exit(0);
		}

	}else{
		echo "DIR NOT FOUND";
		exit(0);
	}



}
?>
<html>
<body>
<center>
<p><b>IPDR</b>
<p>
<form methot=get action=index.php>
Pin:<input type=text name=pin> 
Date:<input type=date name=date placeholder='2018-01-20'>
Time:<input type=time name=time placeholder='13:07' >
<input type=submit name=ok value='Get zip csv'> 
</form>
</center>
</body>
</html>
