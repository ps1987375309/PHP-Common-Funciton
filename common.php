<?php
/**
 * 获取客户端IP地址
 * 
 * @param integer $type
 *        	返回类型 0 返回IP地址 1 返回IPV4地址数字
 * @param boolean $adv
 *        	是否进行高级模式获取（有可能被伪装）
 * @return mixed
 */
function get_client_ip($type = 0, $adv = false) {
	$type = $type ? 1 : 0;
	static $ip = NULL;
	if ($ip !== NULL)
		return $ip [$type];
	if ($adv) {
		if (isset ( $_SERVER ['HTTP_X_FORWARDED_FOR'] )) {
			$arr = explode ( ',', $_SERVER ['HTTP_X_FORWARDED_FOR'] );
			$pos = array_search ( 'unknown', $arr );
			if (false !== $pos)
				unset ( $arr [$pos] );
			$ip = trim ( $arr [0] );
		} elseif (isset ( $_SERVER ['HTTP_CLIENT_IP'] )) {
			$ip = $_SERVER ['HTTP_CLIENT_IP'];
		} elseif (isset ( $_SERVER ['REMOTE_ADDR'] )) {
			$ip = $_SERVER ['REMOTE_ADDR'];
		}
	} elseif (isset ( $_SERVER ['REMOTE_ADDR'] )) {
		$ip = $_SERVER ['REMOTE_ADDR'];
	}
	// IP地址合法验证
	$long = sprintf ( "%u", ip2long ( $ip ) );
	$ip = $long ? array (
			$ip,
			$long 
	) : array (
			'0.0.0.0',
			0 
	);
	return $ip [$type];
}

/**
 * 删除文件及文件夹(可递归)
 * 前提需要文件夹给予可删除权限
 *
 * @param string $path
 *        	删除路径
 * @param bool $recursion
 *        	是否递归删除
 * @return NULL|boolean true:成功，false:失败，null:错误
 */
function delete_path($path, $recursion = true) {
	if (! file_exists ( $path )) {
		return null;
	}
	
	if (is_dir ( $path )) {
		$directory_handle = opendir ( $path );
		if ($directory_handle === false) {
			return null;
		}
		while ( ($entry = readdir ( $directory_handle )) !== false ) {
			if ($entry == '.' || $entry == '..') {
				continue;
			}
			$sub_path = $path . '/' . $entry;
			if (is_dir ( $sub_path ) && $recursion !== true) {
				continue;
			}
			delete_path ( $sub_path );
		}
		closedir ( $directory_handle );
		@rmdir ( $path );
	} else {
		@unlink ( $path );
	}
	
	if (file_exists ( $path )) {
		return false;
	} else {
		return true;
	}
}

/**
 * 远程执行命令(注意语言环境，而且应避免删除等危险操作,显然也可以通过ssh连接其他主机执行操作)
 *
 * @param string $ip
 *        	IP
 * @param int $port
 *        	端口
 * @param string $username
 *        	用户名
 * @param string $password
 *        	密码
 * @param string $string
 *        	执行命令
 * @return array -1：无法连接；-2：认证失败；-3：获取终端失败
 *        
 * @example 参考用例
 *          本地使用root权限执行指令ifconfig -a，并且返回结果（数组）
 *          $result = sshexec('127.0.0.1', 22, 'root', '', 'ifconfig -a');
 */
function ssh_exec($ip, $port, $username, $password, $string) {
	$connect = @ssh2_connect ( $ip, $port );
	if ($connect === false) {
		return array (
				'status' => - 1,
				'result' => null 
		);
	}
	
	$auth = @ssh2_auth_password ( $connect, $username, $password );
	if ($auth === false) {
		return array (
				'status' => - 2,
				'result' => null 
		);
	}
	
	$stdio_stream = ssh2_shell ( $connect, 'xterm' );
	stream_set_blocking ( $stdio_stream, true );
	
	if ($stdio_stream === false) {
		return array (
				'status' => - 3,
				'result' => null 
		);
	}
	$stderr_stream = ssh2_fetch_stream ( $stdio_stream, SSH2_STREAM_STDERR );
	
	$repeat_times = 100;
	$command = preg_replace ( '/;[;]*/', ';', $string );
	// info ( $command, 1 );
	$command = 'echo ' . str_repeat ( '_', $repeat_times ) . '; ' . $command . PHP_EOL;
	fwrite ( $stdio_stream, $command );
	fwrite ( $stdio_stream, 'echo ' . str_repeat ( '_', $repeat_times ) . '; exit;' . PHP_EOL );
	$result = array ();
	while ( ! feof ( $stdio_stream ) ) {
		$line = fgets ( $stdio_stream );
		array_push ( $result, $line );
	}
	fclose ( $stdio_stream );
	fclose ( $stderr_stream );
	
	for($i = 0; $i < count ( $result ); $i ++) {
		if ($result [$i] == (str_repeat ( '_', $repeat_times ) . "\r\n")) {
			if ($result [count ( $result ) - 1] === false) {
				array_pop ( $result );
			}
			if ($result [count ( $result ) - 2] == (str_repeat ( '_', $repeat_times ) . "\r\n")) {
				$end = count ( $result ) - $i - 4;
			} else {
				$end = count ( $result ) - $i - 3;
			}
			$result = array_splice ( $result, $i + 1, $end );
			break;
		}
	}
	
	return array (
			'status' => 0,
			'result' => $result 
	);
}


/**
 * token加密
 * 
 * @param array $data        	
 * @param string $key
 *        	秘钥
 * @return string
 */
function token_encrypt($data) {
	$char = $str = '';
	
	$key = "ea5fedc1a47666138e87012ba71fc78b";
	$x = 0;
	$data = serialize ( $data );
	$len = strlen ( $data );
	
	$l = strlen ( $key );
	for($i = 0; $i < $len; $i ++) {
		if ($x == $l) {
			$x = 0;
		}
		$char .= $key {$x};
		$x ++;
	}
	for($i = 0; $i < $len; $i ++) {
		$str .= chr ( ord ( $data {$i} ) + (ord ( $char {$i} )) % 256 );
	}
	
	return base64_encode ( $str );
}
/**
 * token解密
 * 
 * @param
 *        	string token
 * @param string $key
 *        	秘钥
 * @return array
 */
function token_decrypt($data) {
	$char = $str = '';
	$key = "ea5fedc1a47666138e87012ba71fc78b";
	$x = 0;
	$data = base64_decode ( $data );
	$len = strlen ( $data );
	$l = strlen ( $key );
	for($i = 0; $i < $len; $i ++) {
		if ($x == $l) {
			$x = 0;
		}
		$char .= substr ( $key, $x, 1 );
		$x ++;
	}
	for($i = 0; $i < $len; $i ++) {
		if (ord ( substr ( $data, $i, 1 ) ) < ord ( substr ( $char, $i, 1 ) )) {
			$str .= chr ( (ord ( substr ( $data, $i, 1 ) ) + 256) - ord ( substr ( $char, $i, 1 ) ) );
		} else {
			$str .= chr ( ord ( substr ( $data, $i, 1 ) ) - ord ( substr ( $char, $i, 1 ) ) );
		}
	}
	
	$data = unserialize ( $str );
	
	return $data;
}

/**
 * 调试输出或日志
 */
function _echo($id, $message, $log_prefix = '', $type = true) {
	$directory = RUNTIME_PATH . '/Logger/';
	if (! file_exists ( $directory )) {
		mkdir ( $directory );
	}
	$message = $id . strftime ( ' %F %H:%M:%S ', time () ) . $message . PHP_EOL;
	echo $message;
	
	if ($type) {
		file_put_contents ( strftime ( $directory . $log_prefix . '_%Y%m%d.log', time () ), $message, FILE_APPEND );
	}
}

/**
 * 检测文件编码
 * 
 * @param string $file_path
 *        	文件路径
 * @return string $filesize 默认为空，获取文件的全部内容，如果仅需要获取文件编码类型，获取前一百个字符即可，配合detect_encoding方法使用
 * @return string 返回文件内容，自动换行
 */
function fileToSrting($file_path, $filesize = '') {
	// 判断文件路径中是否含有中文，如果有，那就对路径进行转码，如此才能识别
	if (preg_match ( "/[\x7f-\xff]/", $file_path )) {
		$file_path = iconv ( 'UTF-8', 'GBK', $file_path );
	}
	if (file_exists ( $file_path )) {
		$fp = fopen ( $file_path, "r" );
		if ($filesize === '') {
			$filesize = filesize ( $file_path );
		}
		$str = fread ( $fp, $filesize );
		// 指定读取大小，这里默认把整个文件内容读取出来
		return $str = str_replace ( "\r\n", "\n", $str );
	}
	return file_get_contents ( $file_path );
}

/**
 * 获取文件编码类型
 * 
 * @param string $file_path
 *        	文件路径
 * @param string $filesize
 *        	需要获取的字符长度
 * @return string 返回字符编码
 */
function detect_encoding($file_path, $filesize = '1000') {
	$list = array (
			'GBK',
			'UTF-8',
			'UTF-16LE',
			'UTF-16BE',
			'ISO-8859-1',
			'ANSI' 
	);
	$str = fileToSrting ( $file_path, $filesize );
	if (! $str)
		return false;
	foreach ( $list as $item ) {
		$tmp = mb_convert_encoding ( $str, $item, $item );
		if (md5 ( $tmp ) == md5 ( $str )) {
			return $item;
		}
	}
	return false;
}

/**
 * 自动解析编码读入文件
 * 
 * @param string $file_path
 *        	文件路径
 * @param string $charset
 *        	读取编码
 * @return string 返回读取内容
 */
function auto_read($file_path, $filesize = '', $charset = 'UTF-8') {
	$list = array (
			'UTF-8',
			'GBK',
			'UTF-16LE',
			'UTF-16BE',
			'ISO-8859-1',
			'ANSI' 
	);
	$str = fileToSrting ( $file_path, $filesize );
	foreach ( $list as $item ) {
		$tmp = mb_convert_encoding ( $str, $item, $item );
		if (md5 ( $tmp ) == md5 ( $str )) {
			// var_dump($str, $charset, $item);
			return iconv ( $item, $charset, $str ); // mb_convert_encoding($str, $charset, $item);
		}
	}
	return "";
}

// 检查文件是否有BOM头
function checkBOM($filename) {
	if (! file_exists ( $filename )) {
		return FALSE;
	}
	$contents = file_get_contents ( $filename );
	$charset [1] = substr ( $contents, 0, 1 );
	$charset [2] = substr ( $contents, 1, 1 );
	$charset [3] = substr ( $contents, 2, 1 );
	if (ord ( $charset [1] ) == 239 && ord ( $charset [2] ) == 187 && ord ( $charset [3] ) == 191) {
		return TRUE;
	}
	return FALSE;
}

// 获取某个月的所有时间
function get_day_by_month($time = '', $format = 'Y-m-d') {
	$time = $time != '' ? $time : time (); // 时间戳
	$format = $format != '' ? $format : 'Y-m-d'; // 时间格式
	                                             // 获取当前周几
	$week = date ( 'd', $time );
	$date = [ ];
	for($i = 1; $i <= date ( 't', $time ); $i ++) {
		$date [$i] = date ( $format, strtotime ( '+' . $i - $week . 'days', $time ) );
	}
	return $date;
}

// 获取某周的所有日期
function get_day_by_week($time = '', $format = 'Y-m-d') {
	$time = $time != '' ? $time : time (); // 时间戳
	$format = $format != '' ? $format : 'Y-m-d'; // 时间格式
	                                             // 获取当前周几
	$week = date ( 'w', $time );
	$date = [ ];
	for($i = 1; $i <= 7; $i ++) {
		$date [$i] = date ( $format, strtotime ( '+' . $i - $week . 'days', $time ) );
	}
	return $date;
}

/**
 * 判断ip:端口是否在线
 *
 * @param string $ip
 *        	IP
 * @param int $port
 *        	端口
 * @return boolean true:在线;false:离线
 */
function common_is_online($ip, $port, $timeout = 0.5) {
	$return_value = true;
	$fp = null;
	
	// 需要保证IP、PORT合法
	error_reporting ( E_PARSE | E_ERROR );
	$fp = fsockopen ( $ip, $port, $error_number, $error_string, $timeout );
	if (! $fp) {
		$return_value = false;
	}
	fclose ( $fp );
	return $return_value;
}

/**
 * 获取英文加数字随机数
 *
 * @param $int_len 位数        	
 */
function getRandNumber($int_len) {
	$a_charsArray = array (
			"0",
			"1",
			"2",
			"3",
			"4",
			"5",
			"6",
			"7",
			"8",
			"9",
			"A",
			"B",
			"C",
			"D",
			"E",
			"F",
			"G",
			"H",
			"I",
			"J",
			"K",
			"L",
			"M",
			"N",
			"O",
			"P",
			"Q",
			"R",
			"S",
			"T",
			"U",
			"V",
			"W",
			"X",
			"Y",
			"Z" 
	);
	$int_charsLen = count ( $a_charsArray ) - 1;
	$str_outputstr = "";
	for($i = 0; $i < $int_len; $i ++) {
		$str_outputstr .= $a_charsArray [mt_rand ( 0, $int_charsLen )];
	}
	return $str_outputstr;
}

/**
  * url参数转化成数组
  * @auth xieyang
  * @date 2018年5月10日 13:51:23
  * @param string
  * @return mixed
  */
 function convertUrlArray($query)
 {
 	$queryParts = explode('&', $query);
 	$params = array();
 	foreach ($queryParts as $param) {
 		$item = explode('=', $param);
 		$params[urldecode($item[0])] = urldecode(  $item[1] );
 	}
 	return $params;
 }

/**
  * 把十六进制转二进制
  *
  * @param string $string
  * @return string
  */
 function chr_hexdec($string) {
 	return chr ( hexdec ( $string ) );
 }

 /**
  * 字符串转16进制
  * @param string $string
  * @return string
  * @return:
  */
 function String2Hex( $string = '') {
 	$hex='';
 	for ($i=0; $i < strlen($string); $i++){
 		$hex .= dechex(ord($string[$i]));
 	}
 	return $hex;
 }
 /**
  * 16进制转字符串
  * @param string $string
  * @return string
  * @return:
  */
 function Hex2String($hex){
 	$string='';
 	for ($i=0; $i < strlen($hex)-1; $i+=2){
 		$string .= chr(hexdec($hex[$i].$hex[$i+1]));
 	}
 	return $string;
 }

/**
 * 判断目录空
 *
 * @param string $path        	
 * @return NULL|boolean true:是，false:否，null:错误
 */
function directory_is_empty($path) {
	$path = path_translate ( $path );
	if (! file_exists ( $path ) || ! is_dir ( $path )) {
		return null;
	}
	$directory_handle = opendir ( $path );
	$result = true;
	while ( ($entry = readdir ( $directory_handle )) !== false ) {
		if ($entry == '.' || $entry == '..') {
			continue;
		}
		$result = false;
		break;
	}
	closedir ( $directory_handle );
	return $result;
}

/**
 * (该下载方法支持限速)
 * 支持断点续传、下载速度限制、IE中文文件编码、IE以及Firefox空格处理的下载后端
 *
 * @param string $file_path
 *        	下载文件的绝对路径
 * @param string $file_name
 *        	客户端显示的文件名,不指定或为空时自动获取文件名
 * @param int $max_speed
 *        	下载速度(单位:kb 默认为null不限制)
 * @param int $max_time
 *        	下载超时时间
 *        	
 * @example 参考用例
 *          提供下载链接（非静态文件），下载文件/home/webserver/runtime/schedule.ini，保存为“ini配置文件”
 *          download('/home/webserver/runtime/schedule.ini', 'ini配置文件');
 */
function down_load_new($filePath = null, $file_name = null, $max_speed = 2*1024*1024, $max_time = 30 * 60 * 60) {
	$fp = fopen ( $filePath, "r" );
	set_time_limit ( $max_time );
	// 设置客户端下载的文件名
	if ($file_name === null) {
		$file_name = pathinfo ( $filePath, PATHINFO_FILENAME );
	} else {
		$file_name .= "." . pathinfo ( $filePath, PATHINFO_EXTENSION );
	}
	
	if (preg_match ( '/MSIE/', $_SERVER ['HTTP_USER_AGENT'] ) || preg_match ( '/rv:11\.0/', $_SERVER ['HTTP_USER_AGENT'] )) {
		$file_name = preg_replace ( '/\\ /', '%20', $file_name );
		$file_name = iconv ( 'UTF-8', 'GBK', $file_name );
	}
	// 取得文件大小
	$fileSize = filesize ( $filePath );
	$buffer = $max_speed;
	$bufferCount = 0;
	
	// file_put_contents('./log.txt', json_encode($_SERVER['HTTP_USER_AGENT']) . PHP_EOL, FILE_APPEND);
	header ( "Content-type:application/octet-stream" ); // 设定header头为下载
	header ( 'Content-Disposition: attachment; filename="' . $file_name . '"' );
	if (! empty ( $_SERVER ['HTTP_RANGE'] )) {
		header ( 'Accept-Ranges: bytes' );
		// 切割字符串
		$range = explode ( '-', substr ( $_SERVER ['HTTP_RANGE'], 6 ) );
		fseek ( $fp, $range [0] ); // 移动文件指针到range上
		header ( 'HTTP/1.1 206 Partial Content' );
		header ( "Content-Range: bytes $range[0]-$fileSize/$fileSize" );
		header ( "content-length:" . $fileSize - $range [0] );
		$buffer = $buffer / 10;
	} else {
		header ( 'HTTP/1.1 200 OK' );
		header ( 'Accept-Ranges: bytes' );
		header ( 'content-Length: ' . $fileSize );
	}
	
	ob_end_clean (); // 缓冲区结束
	ob_implicit_flush (); // 强制每当有输出的时候,即刻把输出发送到浏览器
	header ( 'X-Accel-Buffering: no' ); // 不缓冲数据
	if ($buffer) {
		while ( ! feof ( $fp ) && $fileSize - $bufferCount > 0 ) { // 循环读取文件数据
			$data = fread ( $fp, $buffer );
			$bufferCount += $buffer;
			echo $data; // 输出文件
			sleep ( 1 );
		}
	}
	
	fclose ( $fp );
}

/**
 * 转换文件格式(1.将文件转换为pdf格式;2.将pdf文件转换为swf文件)
 *
 * @param string $inpath
 *        	文件绝对路径
 * @param string $type
 *        	文件转化类型 接收常用的doc，xls，ppts等office格式 和 pdf
 * @param mixed $outpath
 *        	文件保存路径，不指定为原文件路径
 * @return bool|mixed|string 成功返回pdf文件路径失败返回false
 */
function transform_file($inpath, $type = 'pdf', $outpath = null) {
	if (! file_exists ( $inpath )) {
		return true;
	}
	// 没有指定输出文件夹时，使用但前文件夹保存
	if ($outpath == null) {
		$outpath = substr ( $inpath, 0, strrpos ( $inpath, '/' ) );
	}
	
	$new = preg_replace ( '/\..*$/', '.' . $type, $inpath );
	$ext = substr ( strrchr ( $inpath, '.' ), 1 );
	// 如果是excel文件先转称html,返回html的路径再转pdf
	/*
	 * if( in_array( strtolower( $ext ) , [ 'xls' , 'xlsx'] ) ){
	 * $inpath = transform_excel_to_html( $inpath );
	 * }
	 */
	// 开始 转换
	if ($type == 'pdf') {
		// txt文本需要进行编码转换称utf8
		if ($ext == 'txt') {
			$utf8Str = auto_read ( $inpath );
			if (! checkBOM ( $inpath )) {
				$utf8Str = "\xEF\xBB\xBF" . $utf8Str;
			}
			file_put_contents ( $inpath, $utf8Str );
		}
		$libreoffice = config ( 'LIBREOFFICE_BINARY' );
		// $command = "$libreoffice --headless --convert-to pdf --outdir " . $outpath . " " . $inpath." > /dev/null 2>&1 &";
		$command = "$libreoffice --headless --convert-to pdf --outdir " . $outpath . " " . $inpath . " > /dev/null 2>&1 &";
		 
		$res = exec ( $command );
	} else if ($type == 'swf') {
		if (mime_content_type ( $inpath ) != 'application/pdf') {
			return true;
		}
		
		$pdf2swf = config ( 'PDF2SWF_BINARY' );
		$command = "$pdf2swf " . $inpath . " " . $new . " > /dev/null 2>&1 &";
		$res = exec ( $command );
	}
}

/**
 * excel转html
 * 
 * @param unknown $excelpath        	
 */
function transform_excel_to_html($excelpath = '') {
	$file_type = substr ( strrchr ( $excelpath, '.' ), 1 );
	$PHPExcel = new \PHPExcel ();
	if ($file_type == "xlsx" || $file_type == "XLSX") {
		// 不同的excel版本，不同引入
		$PHPReader = new \PHPExcel_Reader_Excel2007 ();
	} else {
		$PHPReader = new \PHPExcel_Reader_Excel5 ();
	}
	$PHPExcel = $PHPReader->load ( $excelpath );
	$pathinfo = pathinfo ( $excelpath );
	$savePath = $pathinfo ['dirname'] . DS . $pathinfo ['filename'] . '.html'; // 这里直接改为word后缀即可
	
	$objWriter = new PHPExcel_Writer_HTML ( $PHPExcel );
	
	$objWriter->setUseInlineCss ( true ); // 采用内联样式
	$objWriter->setSheetIndex ( 0 );
	$objWriter->save ( $savePath );
	return $savePath;
}
function transform_file_pdf($inpath, $type = 'pdf') {
	if (! file_exists ( $inpath )) {
		return "file does not exists!";
	}
	// 没有指定输出文件夹时，使用但前文件夹保存
	if ($outpath == null) {
		$outpath = substr ( $inpath, 0, strrpos ( $inpath, '/' ) );
	}
	
	$new = preg_replace ( '/\..*$/', '.' . $type, $inpath );
	
	// 开始 转换
	if ($type == 'pdf') {
		$libreoffice = config ( 'LIBREOFFICE_BINARY' );
		
		$command = "$libreoffice --headless --convert-to pdf --outdir " . $outpath . " " . $inpath . "  > /dev/null 2>&1 &";
		
		$res = exec ( $command );
	}
	if (is_file ( $new )) {
		return $new;
	} else {
		return false;
	}
}

