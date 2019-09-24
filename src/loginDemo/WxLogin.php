<?php

namespace Home\Controller;

use Think\Controller;

class WxLogin extends Controller {

    /*

    * 自动执行

    */

    public function _initialize(){

        //判断是否在微信打开

        $ua = $_SERVER['HTTP_USER_AGENT'];

        //MicroMessenger 是android/iphone版微信所带的

        //Windows Phone 是winphone版微信带的  (这个标识会误伤winphone普通浏览器的访问)

        if(strpos($ua, 'MicroMessenger') == false && strpos($ua, 'Windows Phone') == false){

            //普通浏览器

            if(!$_SESSION['username']) {

                header('Location:xxx');

            }

        }else{

            //微信浏览器

            $users = M('User');

            $appid = 'xxx';

            $secret = 'xxx';

            if(!$_SESSION['username']) {

                //微信网页授权

                $redirect_uri = urlencode ('http://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']);

                $url ="https://open.weixin.qq.com/connect/oauth2/authorize?appid=$appid&redirect_uri=$redirect_uri&response_type=code&scope=snsapi_userinfo&state=1&connect_redirect=1#wechat_redirect";

                header("Location:".$url);

                $code = $_GET["code"];



                //第一步:取得openid

                $oauth2Url = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=$appid&secret=$secret&code=$code&grant_type=authorization_code";

                $oauth2 = $this->getJson($oauth2Url);

                //第二步:根据全局access_token和openid查询用户信息

                $access_token = $oauth2["access_token"];

                $openid = $oauth2['openid'];

                $get_user_info_url = "https://api.weixin.qq.com/sns/userinfo?access_token=$access_token&openid=$openid&lang=zh_CN";

                $userinfo = $this->getJson($get_user_info_url);

                //save用户信息

                if($userinfo['openid']){

                    $username = $userinfo['openid'];

                    $nickname = $userinfo['nickname'];

                    $headimg = $userinfo['headimgurl'];

                    $province = $userinfo['province'];

                    $city = $userinfo['city'];

                    $sex = $userinfo['sex'];

                    $user = $users->where(array('username' => $username))->find();

                    if ($user) {

                        $users->where(array('username' => $username))->save(array('nickname' => $nickname, 'avatar' => $headimg, 'lasttime' => time()));

                    }else{

                        $users->add(array('username' => $username, 'nickname' => $nickname, 'avatar' => $headimg, 'province' => $province, 'city' => $city, 'gender' => $sex, 'regtime' => time(), 'lasttime' => time()));

                        // $data = array('username' => $username, 'nickname' => $nickname, 'avatar' => $headimg, 'province' => $province, 'city' => $city, 'gender' => $sex, 'regtime' => time(), 'lasttime' => time());

                    }

                    $_SESSION['username'] = $username;

                    if($user['tel'] == NULL){

                        //如果用户手机号为空的话跳转到绑定手机号页面

                        header('Location:xxx');

                    }

                }

            }else{

                $user = D('User')->getUserInfo();  //getUserInfo()是model根据session('username')获取用户数据的方法

                if($user['tel'] == NULL){

                    header('Location:xxx');

                }

            }



            //获取接口调用凭证access_token

            $accessurl = 'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid='.$appid.'&secret='.$secret;

            $access_token = S('access_token');

            if(!$access_token){

                $access = $this->getJson($accessurl);

                if(!empty($access['access_token'])){

                    S('access_token',$access['access_token'],$access['expires_in']);

                }

            }

            //分享

            /*$share = new WechatShare($appid, $_SESSION['username']);

            $this->shareScript = $share->getSgin($access_token);

            $this->assign('shareScript', $this->shareScript);

            $this->assign('sharewechaid', $_SESSION['username']);

            if($_GET['sharewechaid']){

                $this->assign('getsharewechaid', $_GET['sharewechaid']);

            }*/

        }



    }



    public function getJson($url){

        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);

        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);

        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        $output = curl_exec($ch);

        curl_close($ch);

        return json_decode($output, true);

    }

}