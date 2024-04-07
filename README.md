<div align="center">
<img src="https://i.imgur.com/xV6HY67.jpeg">

<br>

___

<br>

<img src="https://img.shields.io/github/license/oppsec/breads?color=blue&logo=github&style=for-the-badge">
<img src="https://img.shields.io/github/issues/oppsec/breads?color=blue&logo=github&style=for-the-badge">
<img src="https://img.shields.io/github/stars/oppsec/breads?color=blue&logo=github&style=for-the-badge">
<img src="https://img.shields.io/github/forks/oppsec/breads?color=blue&logo=github&style=for-the-badge">
<img src="https://img.shields.io/github/languages/code-size/oppsec/breads?color=blue&logo=github&style=for-the-badge">

</div>

<br>

<h3> BREADS - BREaking Active Directory Security </h2>
<p> <b>BREADS</b> is a tool focused on enumerating and attacking Active Directory environments through LDAP and SMB protocols. This project is inspired by other existing tools like NetExec (CrackMapExec) and Impacket. </p>

<br>

<h3> Features </h3>
<ul>
    <li>Profile management</li>
    <li>Support Kerberoasting</li>
    <li>Change User Password</li>
    <li>Add User to Group</li>
    <li>ACEs Enumeration</li>
    <li>Interactive Shell</li>
    <li>Support to Pass-The-Hash</li>
    <li>Others</li>
</ul>

<br>

<h3> Installation </h3>
<pre>
~$ apt install pipx
~$ pipx ensurepath
~$ pipx install git+https://github.com/oppsec/breads.git
~$ breads-ad
</pre>

- Arch Linux based Distros: If you encounter any error when trying to install you might use <b>--break-system-packages</b> flag

<br>

<h3> Updating </h4>
<pre>
~$ pipx install git+https://github.com/oppsec/breads.git --force
<br>
or
<br>
~$ pipx reinstall breads-ad --python /usr/bin/python
</pre>

<br>

<h3> Preview usage </h3>
<a href="https://asciinema.org/a/647121" target="_blank"><img src="https://asciinema.org/a/647121.svg" /></a>

<br>

<h3> Warning </h3>
<p> The developer is not responsible for any malicious use of this tool </p>

<br>

<h3> Credits </h3>
<ul>
    <li>NetExec (CrackMapExec)</li>
    <li>Impacket</li>
</ul>