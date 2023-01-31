rule Behinder_aspx {
   meta:
      description = "Behinder - file shell.aspx"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-26"
      hash1 = "224c7f43f72938e44b4f164c1c899c398a9c099a92c6d084856f5e227761e3b0"
   strings:
      $x1 = "<%@ Page Language=\"C#\" %><%@Import Namespace=\"System.Reflection\"%><%Session.Add(\"k\",;" ascii
      $s3 = "ssion[0] + \"\"),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged()." ascii
      $s4 = "eateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance(\"U\").Equals(this);%>" fullword ascii
   condition:
      uint16(0) == 0x253c and filesize < 1KB and
      1 of ($x*) and all of them
}

rule Behinder_php {
   meta:
      description = "Behinder - file shell.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-26"
      hash1 = "3566561d818e868a96f2bc8db9c93663a4fb81c06041259f66d04147d50ce8ab"
   strings:
      $s1 = "$post=openssl_decrypt($post, \"AES128\", $key);" fullword ascii
      $s2 = "$post=file_get_contents(\"php://input\");" fullword ascii
      $s3 = " $post[$i] = $post[$i]^$key[$i+1&15]; " fullword ascii
      $s4 = "$_SESSION['k']=$key;" fullword ascii
      $s5 = "@error_reporting(0);" fullword ascii
      $s6 = "$post=$t($post.\"\");" fullword ascii
      $s7 = "for($i=0;$i<strlen($post);$i++) {" fullword ascii
      $s8 = "$t=\"base64_\".\"decode\";" fullword ascii
      $s9 = "if(!extension_loaded('openssl'))" fullword ascii
      $s10 = "    $arr=explode('|',$post);" fullword ascii
      $s11 = "class C{public function __invoke($p) {eval($p.\"\");}}" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}

rule shell_jspx {
   meta:
      description = "Behinder - file shell.jspx.jsp"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-26"
      hash1 = "a8d79695c9b23ad3a157f112863144fd8a196aae5c3fcb4e52b0ab4d1bf64367"
   strings:
      $x1 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"1.2\"><jsp:directive.page import=\"java.util.*,javax.crypto.*,jav" ascii
      $s2 = ";c.init(2,new SecretKeySpec((session.getValue(\"u\")+\"\").getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFi" ascii
      $s3 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"1.2\"><jsp:directive.page import=\"java.util.*,javax.crypto.*,jav" ascii
      $s4 = "ypto.spec.*\"/><jsp:declaration> class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.de" ascii
      $s5 = "w sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);</jsp:scriptlet></js" ascii
      $s6 = "session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"" ascii
      $s7 = "p:root>" fullword ascii
   condition:
      uint16(0) == 0x6a3c and filesize < 1KB and
      1 of ($x*) and all of them
}

rule Behinder_asp {
   meta:
      description = "Behinder - file shell.asp"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-26"
      hash1 = "2c87faf7c25688c83c86c8b1e9f706f98a4195b84d1f5ce3169de6f2997320f7"
   strings:
      $s1 = "content=Request.BinaryRead(size)" fullword ascii
      $s2 = "execute(result)" fullword ascii
      $s3 = "result=result&Chr(ascb(midb(content,i,1)) Xor Asc(Mid(k,(i and 15)+1,1)))" fullword ascii
      $s4 = "Session(\"k\")=k" fullword ascii
      $s5 = "Response.CharSet = \"UTF-8\" " fullword ascii
      $s6 = "size=Request.TotalBytes" fullword ascii
      $s7 = "For i=1 To size" fullword ascii
   condition:
      uint16(0) == 0x253c and filesize < 1KB and
      all of them
}

rule Behinder_jsp {
   meta:
      description = "Behinder - file shell.jsp"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-26"
      hash1 = "5c8c2d64aef4e586b077b5fde7d8fc3aea16ae9d15438b516ec277c42a7164a5"
   strings:
      $x1 = "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}pub" ascii
      $s2 = "ader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext" ascii
      $s3 = "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}pub" ascii
      $s4 = "c Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\"))" ascii
      $s5 = "Value(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getC" ascii
   condition:
      uint16(0) == 0x253c and filesize < 1KB and
      1 of ($x*) and all of them
}

rule shell_java9 {
   meta:
      description = "Behinder - file shell_java9.jsp"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-26"
      hash1 = "cfd86cc11928d594f4ccfb6be371a09383f83bbe82d4d6d86703f5fa6b5233f2"
   strings:
      $x1 = "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}pub" ascii
      $s2 = "ader()).g(c.doFinal(Base64.getDecoder().decode(request.getReader().readLine()))).newInstance().equals(pageContext);}%>" fullword ascii
      $s3 = "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}pub" ascii
      $s4 = "c Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=" ascii
      $s5 = "Value(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getC" ascii
   condition:
      uint16(0) == 0x253c and filesize < 1KB and
      1 of ($x*) and all of them
}


