use strict;
use warnings;
use XML::LibXML;
use File::Basename;
use File::Path;
use File::stat;
use File::Copy;
#use File::Slurp;
use File::Temp qw/ tempfile /;
use POSIX;
use Cwd;

File::Temp->safe_level( File::Temp::HIGH );

my $defaultConfig = $ARGV[1] or die;

my $dom = XML::LibXML->load_xml(location => $ARGV[0]);

sub get { my ($name) = @_; return $dom->findvalue("/expr/attrs/attr[\@name = '$name']/*/\@value"); }

sub readBinFile {
    my ($fn) = @_; local $/ = undef;
    open FILE, "<$fn" or return undef; my $s = <FILE>; close FILE;
    return $s;
}

sub readFile {
    my ($fn) = @_; local $/ = undef;
    open FILE, "<$fn" or return undef; my $s = <FILE>; close FILE;
    local $/ = "\n"; chomp $s; return $s;
}

sub writeFile {
    my ($fn, $s) = @_;
    open FILE, ">$fn" or die "cannot create $fn: $!\n";
    print FILE $s or die;
    close FILE or die;
}

sub generateLcp {
    my ($tboot, $tbootCmd, $public, $private) = @_;
    # Generate public key from private key if needed.
    my (undef, $fn) = tempfile( SUFFIX => '.pem', UNLINK => 1);
    -e $private || die "Private key $private does not exist! Create one the command openssl genrsa -out $private 2048";
    if ((! -e $public) && $private) {
	`openssl rsa -pubout -in $private -out $fn`;
        $public = $fn;
    }

    # Create LCP policy
    # Create MLE element
    print STDERR "Generaring MLE hash for tboot... ";
    my (undef, $mle_hash) = tempfile(UNLINK => 1);
    `lcp_mlehash -c "$tbootCmd" /boot$tboot >$mle_hash`;
    print STDERR readFile($mle_hash)."\n";
    my (undef, $mle_elt) = tempfile(UNLINK => 1);
    print STDERR "Generating MLE element for tboot...\n";
    `lcp_crtpolelt --create --type mle --ctrl 0x00 --minver 67 --out $mle_elt $mle_hash`;

    # SBIOS element
    my (undef, $list_unsig) = tempfile(UNLINK => 1);
    my (undef, $list_sig) = tempfile(UNLINK => 1);
    print STDERR "Generating policy lists from MLE element for tboot...\n";
    `lcp_crtpollist --create --out $list_unsig $mle_elt`;
    `lcp_crtpollist --create --out $list_sig $mle_elt`;

    # The resulting policy and data
    my (undef, $list_pol) = tempfile(UNLINK => 1);
    my (undef, $list_data) = tempfile(UNLINK => 1);

    # Sign the list using openssl
    if ($private) {
        # TODO: Verify how $list is handled here.
        # Add our public key to the list
        print STDERR "Adding public key to policy list for tboot...\n";
	`lcp_crtpollist --sign --pub $public --nosig --out $list_sig`;
	# TODO: Add scheme where we can import this signature from somewhere else.
        # Create signature for the list
	my ($_,$fn) = tempfile();
        print STDERR "Signing policy list for tboot...\n";
	`openssl dgst -sha1 -sign $private -out $fn $list_sig`;
	# Add the signature to the list (so we have the public key and the signature as additional elements)
        print STDERR "Adding signature to policy list for tboot...\n";
        `lcp_crtpollist --addsig --sig $fn --out $list_sig`;
        print STDERR "Creating final Launch Control Policy (LCP) for tboot...\n";
        `lcp_crtpol2 --create --type list --pol $list_pol --data $list_data $list_unsig $list_sig`;
    } else {
        print STDERR "Creating final Launch Control Policy (LCP) for tboot...\n";
        `lcp_crtpol2 --create --type list --pol $list_pol --data $list_data $list_unsig`;
    }
    return (readBinFile($list_pol), readBinFile($list_data));
}

# Instruct tboot on which kernel/initrd to boot by creating a
# verified launch policy
sub generateTbootPolicy {
    my ($kernel, $kernelCmd, $initrd, $initrdCmd) = @_;
    #my (undef, $vl_policy) = tempfile(UNLINK => 1);
    #my (undef, $fn) = tempfile( SUFFIX => '.pem', UNLINK => 1);
    my (undef, $vl_policy) = tempfile( OPEN => 0 );
    print STDERR "Creating tboot verified launch policy...\n";
    `tb_polgen --create --type nonfatal $vl_policy`;
    print STDERR "Adding verified launch element for kernel...\n";
    `tb_polgen --add --num 0 --pcr 18 --hash image --cmdline "$kernelCmd" --image /boot$kernel $vl_policy`;
    print STDERR "Adding verified launch element for initrd...\n";
    `tb_polgen --add --num 1 --pcr 19 --hash image --cmdline "$initrdCmd" --image /boot$initrd $vl_policy`;
    return readBinFile($vl_policy);
}

sub writeTpmNvram {
    my ($lcp_pol, $vl_pol) = @_;
    # Define LCP and Verified Launch policy indices
    # The nvram index 0x20000001 is hard-coded in tboot
    `tpm_nvinfo -n | grep -q 0x20000001`;
    if ($?) {
	print STDERR "Creating tboot policy index in the TPM NVRAM\n";
        `tpm_nvdefine -i 0x20000001 -s 512 -p 'OWNERWRITE' -z -y`;
        ($? == 0) || die "Could not create tboot policy index in the TPM NVRAM";
    } else {
	print STDERR "Tboot policy index exists in the TPM NVRAM\n";
    }
    # The owner index is sometimes pre-defined on delivery of the system
    # TODO: Add tpm owner password
    `tpm_nvinfo -n | grep -q 0x40000001`;
    if ($?) {
	print STDERR "Creating LCP index in the TPM NVRAM\n";
	`tpm_nvdefine -i 0x40000001 -s 54 -p 'OWNERWRITE' -z -y`;
        ($? == 0) || die "Could not create LCP index in the TPM NVRAM";
    } else {
	print STDERR "LCP index exists in the TPM NVRAM\n";
    }
    my (undef, $lcp_policy) = tempfile(UNLINK => 1);
    my (undef, $vl_policy) = tempfile(UNLINK => 1);
    writeFile($lcp_policy, $lcp_pol);
    writeFile($vl_policy, $vl_pol);
    # TODO: Add TPM password
    my $display = `lcp_crtpol2 --show $lcp_policy`;
    print STDERR "Writing policy: $display\n";
    #`lcp_writepol -i owner -f $lcp_policy`;
    `tpm_nvwrite -z -i 0x40000001 -f $lcp_policy`;
    ($? == 0) || die "Failed to write LCP index in the TPM NVRAM";
    print STDERR "Success\n";
    $display = `lcp_crtpol2 --show $vl_policy`;
    print STDERR "Writing policy: $display\n";
    #`lcp_writepol -i 0x20000001 -f $vl_policy`;
    `tpm_nvwrite -z -i 0x20000001 -f $vl_policy`;
    ($? == 0) || die "Failed to write tboot index in the TPM NVRAM";
    print STDERR "Success\n";
}

# (add module /list.data to grub)
   

my $grub = get("grub");
my $grubVersion = int(get("version"));
my $extraConfig = get("extraConfig");
my $extraPrepareConfig = get("extraPrepareConfig");
my $extraPerEntryConfig = get("extraPerEntryConfig");
my $extraEntries = get("extraEntries");
my $extraEntriesBeforeNixOS = get("extraEntriesBeforeNixOS") eq "true";
my $splashImage = get("splashImage");
my $configurationLimit = int(get("configurationLimit"));
my $copyKernels = get("copyKernels") eq "true";
my $timeout = int(get("timeout"));
my $defaultEntry = int(get("default"));
my $trustedBootEnable = get("trustedBootEnable") eq "true";
my $trustedBootAutoLcp = get("trustedBootAutoLcp") eq "true";
my $trustedBootTbootParams = get("trustedBootTbootParams");
my $trustedBootLcpPublicKey = get("trustedBootLcpPublicKey");
my $trustedBootLcpPrivateKey = get("trustedBootLcpPrivateKey");
my $tbootPath = get("tbootPath");
$ENV{'PATH'} = get("path");

die "unsupported GRUB version\n" if $grubVersion != 1 && $grubVersion != 2;

print STDERR "updating GRUB $grubVersion menu...\n";

mkpath("/boot/grub", 0, 0700);


# Discover whether /boot is on the same filesystem as / and
# /nix/store.  If not, then all kernels and initrds must be copied to
# /boot, and all paths in the GRUB config file must be relative to the
# root of the /boot filesystem.  `$bootRoot' is the path to be
# prepended to paths under /boot.
my $bootRoot = "/boot";
if (stat("/")->dev != stat("/boot")->dev) {
    $bootRoot = "";
    $copyKernels = 1;
} elsif (stat("/boot")->dev != stat("/nix/store")->dev) {
    $copyKernels = 1;
}


# Generate the header.
my $conf .= "# Automatically generated.  DO NOT EDIT THIS FILE!\n";

if ($grubVersion == 1) {
    $conf .= "
        default $defaultEntry
        timeout $timeout
    ";
    if ($splashImage) {
        copy $splashImage, "/boot/background.xpm.gz" or die "cannot copy $splashImage to /boot\n";
        $conf .= "splashimage $bootRoot/background.xpm.gz\n";
    }
}

else {
    $conf .= "
        if [ -s \$prefix/grubenv ]; then
          load_env
        fi

        # ‘grub-reboot’ sets a one-time saved entry, which we process here and
        # then delete.
        if [ \"\${saved_entry}\" ]; then
          # The next line *has* to look exactly like this, otherwise KDM's
          # reboot feature won't work properly with GRUB 2.
          set default=\"\${saved_entry}\"
          set saved_entry=
          set prev_saved_entry=
          save_env saved_entry
          save_env prev_saved_entry
          set timeout=1
        else
          set default=$defaultEntry
          set timeout=$timeout
        fi

        if loadfont $bootRoot/grub/fonts/unicode.pf2; then
          set gfxmode=640x480
          insmod gfxterm
          insmod vbe
          terminal_output gfxterm
        fi
    ";

    if ($splashImage) {
        # FIXME: GRUB 1.97 doesn't resize the background image if it
        # doesn't match the video resolution.
        copy $splashImage, "/boot/background.png" or die "cannot copy $splashImage to /boot\n";
        $conf .= "
            insmod png
            if background_image $bootRoot/background.png; then
              set color_normal=white/black
              set color_highlight=black/white
            else
              set menu_color_normal=cyan/blue
              set menu_color_highlight=white/blue
            fi
        ";
    }
}

$conf .= "$extraConfig\n";


# Generate the menu entries.
$conf .= "\n";

my %copied;
mkpath("/boot/kernels", 0, 0755) if $copyKernels;

sub copyToKernelsDir {
    my ($path) = @_;
    return $path unless $copyKernels;
    $path =~ /\/nix\/store\/(.*)/ or die;
    my $name = $1; $name =~ s/\//-/g;
    my $dst = "/boot/kernels/$name";
    # Don't copy the file if $dst already exists.  This means that we
    # have to create $dst atomically to prevent partially copied
    # kernels or initrd if this script is ever interrupted.
    if (! -e $dst) {
        my $tmp = "$dst.tmp";
        copy $path, $tmp or die "cannot copy $path to $tmp\n";
        rename $tmp, $dst or die "cannot rename $tmp to $dst\n";
    }
    $copied{$dst} = 1;
    return "$bootRoot/kernels/$name";
}

sub addEntry {
    my ($name, $path, $isDefault) = @_;
    return unless -e "$path/kernel" && -e "$path/initrd";

    my $kernel = copyToKernelsDir(Cwd::abs_path("$path/kernel"));
    my $initrd = copyToKernelsDir(Cwd::abs_path("$path/initrd"));
    my $xen = -e "$path/xen.gz" ? copyToKernelsDir(Cwd::abs_path("$path/xen.gz")) : undef;
    my $tboot = $trustedBootEnable ? copyToKernelsDir($tbootPath."/boot/tboot.gz") : undef;

    # FIXME: $confName

    my $kernelParams =
        "systemConfig=" . Cwd::abs_path($path) . " " .
        "init=" . Cwd::abs_path("$path/init") . " " .
        readFile("$path/kernel-params");
    my $xenParams = $xen && -e "$path/xen-params" ? readFile("$path/xen-params") : "";
    
    # Configure tboot and/or xen in a multiboot setup.
    my $multiboot = undef;
    $multiboot = (($grubVersion == 1) ? "  kernel" : "  multiboot") if ($xen || $trustedBootEnable);
    my $extra_line = undef;
    if ($trustedBootEnable) {
        # Tboot must be repeated on cmdline because grub doesn't properly pass argv[0]
        $multiboot .= " $tboot $tboot $trustedBootTbootParams\n";
        $multiboot .= "  module $xen $xenParams\n" if $xen;

	if ($isDefault && $trustedBootAutoLcp) {
            print STDERR "Generating Launch Control Policy and Verified Launch Policy\n";
	    my ($list_pol, $list_data) = generateLcp($tboot,
                                                     $trustedBootTbootParams,
                                                     $trustedBootLcpPublicKey,
 	                                             $trustedBootLcpPrivateKey);
	    my $vl_policy = generateTbootPolicy($kernel, $kernelParams, $initrd, "");
            print STDERR "Writing LCP and VLP to NVRAM\n";
            writeTpmNvram($list_pol, $vl_policy);
            # Create tmp file on /boot with module data.
	    my (undef, $f) = tempfile( SUFFIX => '.lcp-data', UNLINK => 1);
            writeFile($f, $list_data);
	    my $list_data_fn = copyToKernelsDir($f);
            print STDERR "Copying $f to $list_data_fn\n";
            $extra_line = "  module $list_data_fn\n";
        }
    } elsif ($xen) {
        $multiboot .= " $xen $xenParams\n";
    }
    
    if ($grubVersion == 1) {
        $conf .= "title $name\n";
        $conf .= "  $extraPerEntryConfig\n" if $extraPerEntryConfig;
        $conf .= $multiboot if $multiboot;
        $conf .= "  " . ($multiboot ? "module" : "kernel") . " $kernel $kernelParams\n";
        $conf .= "  " . ($multiboot ? "module" : "initrd") . " $initrd\n\n";
        $conf .= $extra_line if $extra_line;
    } else {
        $conf .= "menuentry \"$name\" {\n";
        $conf .= "  $extraPerEntryConfig\n" if $extraPerEntryConfig;
        $conf .= $multiboot if $multiboot;
        $conf .= "  " . ($multiboot ? "module" : "linux") . " $kernel $kernelParams\n";
        $conf .= "  " . ($multiboot ? "module" : "initrd") . " $initrd\n";
        $conf .= $extra_line if $extra_line;
        $conf .= "}\n\n";
    }
}


# Add default entries.
$conf .= "$extraEntries\n" if $extraEntriesBeforeNixOS;

addEntry("NixOS - Default", $defaultConfig, 1);

$conf .= "$extraEntries\n" unless $extraEntriesBeforeNixOS;

# extraEntries could refer to @bootRoot@, which we have to substitute
$conf =~ s/\@bootRoot\@/$bootRoot/g;

# Add entries for all previous generations of the system profile.
$conf .= "submenu \"NixOS - All configurations\" {\n" if $grubVersion == 2;

sub nrFromGen { my ($x) = @_; $x =~ /system-(.*)-link/; return $1; }

my @links = sort
    { nrFromGen($b) <=> nrFromGen($a) }
    (glob "/nix/var/nix/profiles/system-*-link");

my $curEntry = 0;
foreach my $link (@links) {
    last if $curEntry++ >= $configurationLimit;
    my $date = strftime("%F", localtime(lstat($link)->mtime));
    my $version =
        -e "$link/nixos-version"
        ? readFile("$link/nixos-version")
        : basename((glob(dirname(Cwd::abs_path("$link/kernel")) . "/lib/modules/*"))[0]);
    addEntry("NixOS - Configuration " . nrFromGen($link) . " ($date - $version)", $link);
}

$conf .= "}\n" if $grubVersion == 2;

# Run extraPrepareConfig in sh
if ($extraPrepareConfig ne "") {
  system((get("shell"), "-c", $extraPrepareConfig));
}

# Atomically update the GRUB config.
my $confFile = $grubVersion == 1 ? "/boot/grub/menu.lst" : "/boot/grub/grub.cfg";
my $tmpFile = $confFile . ".tmp";
writeFile($tmpFile, $conf);
rename $tmpFile, $confFile or die "cannot rename $tmpFile to $confFile\n";


# Remove obsolete files from /boot/kernels.
foreach my $fn (glob "/boot/kernels/*") {
    next if defined $copied{$fn};
    print STDERR "removing obsolete file $fn\n";
    unlink $fn;
}


# Install GRUB if the version changed from the last time we installed
# it.  FIXME: shouldn't we reinstall if ‘devices’ changed?
my $prevVersion = readFile("/boot/grub/version") // "";
if (($ENV{'NIXOS_INSTALL_GRUB'} // "") eq "1" || get("fullVersion") ne $prevVersion) {
    foreach my $dev ($dom->findnodes('/expr/attrs/attr[@name = "devices"]/list/string/@value')) {
        $dev = $dev->findvalue(".") or die;
        next if $dev eq "nodev";
        print STDERR "installing the GRUB $grubVersion boot loader on $dev...\n";
        system("$grub/sbin/grub-install", "--recheck", Cwd::abs_path($dev)) == 0
            or die "$0: installation of GRUB on $dev failed\n";
    }
    writeFile("/boot/grub/version", get("fullVersion"));
}
