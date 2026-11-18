# Creates the LinkScope icon (if missing) and Desktop + Start Menu shortcuts.
# Run:  powershell -ExecutionPolicy Bypass -File install-shortcut.ps1
# Then right-click the Desktop icon -> "Pin to taskbar" (Windows doesn't allow
# scripts to pin).
#
# The shortcut carries an AppUserModelID that matches the one the app sets at
# startup, so the pinned icon and the running window share one taskbar button
# instead of showing up as a separate "Python" button.

$ErrorActionPreference = 'Stop'
$AppId = 'LinkScope.NetworkDebugger'
$here  = Split-Path -Parent $MyInvocation.MyCommand.Path
$app   = Join-Path $here 'linkscope.pyw'
$ico   = Join-Path $here 'linkscope.ico'

# ------------------------------------------------------------------ icon
function New-LinkScopeIcon($path) {
    Add-Type -AssemblyName System.Drawing
    $sizes = 16, 24, 32, 48, 64, 128, 256
    $pngs = foreach ($s in $sizes) {
        $bmp = New-Object Drawing.Bitmap $s, $s
        $g = [Drawing.Graphics]::FromImage($bmp)
        $g.SmoothingMode = 'AntiAlias'
        $g.Clear([Drawing.Color]::Transparent)
        $k = $s / 256.0
        # rounded square background
        $r = 56 * $k; $m = 8 * $k; $w = $s - 2 * $m
        $bg = New-Object Drawing.Drawing2D.GraphicsPath
        $bg.AddArc($m, $m, $r, $r, 180, 90); $bg.AddArc($m + $w - $r, $m, $r, $r, 270, 90)
        $bg.AddArc($m + $w - $r, $m + $w - $r, $r, $r, 0, 90); $bg.AddArc($m, $m + $w - $r, $r, $r, 90, 90)
        $bg.CloseFigure()
        $brush = New-Object Drawing.Drawing2D.LinearGradientBrush (New-Object Drawing.PointF 0, 0), (New-Object Drawing.PointF 0, $s), ([Drawing.Color]::FromArgb(255, 24, 92, 170)), ([Drawing.Color]::FromArgb(255, 12, 52, 110))
        $g.FillPath($brush, $bg)
        # RJ45 jack outline (white)
        $white = [Drawing.Color]::White
        $pen = New-Object Drawing.Pen $white, ([Math]::Max(1.5, 14 * $k))
        $pen.LineJoin = 'Round'
        $jack = New-Object Drawing.Drawing2D.GraphicsPath
        $pts = @((60, 92), (196, 92), (196, 178), (156, 178), (156, 198), (100, 198), (100, 178), (60, 178)) |
            ForEach-Object { New-Object Drawing.PointF ($_[0] * $k), ($_[1] * $k) }
        $jack.AddPolygon([Drawing.PointF[]]$pts)
        $g.DrawPath($pen, $jack)
        # contact pins
        if ($s -ge 32) {
            $pinBrush = New-Object Drawing.SolidBrush $white
            for ($i = 0; $i -lt 6; $i++) {
                $x = (84 + $i * 16) * $k
                $g.FillRectangle($pinBrush, [single]$x, [single](106 * $k), [single][Math]::Max(1, 8 * $k), [single](24 * $k))
            }
        }
        # green "link" dot
        $d = 56 * $k
        $g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(255, 60, 220, 120))), [single](178 * $k), [single](22 * $k), [single]$d, [single]$d)
        $g.Dispose()
        $ms = New-Object IO.MemoryStream
        $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()
        , @($s, $ms.ToArray())
    }
    # ICO container with PNG payloads
    $out = New-Object IO.MemoryStream
    $bw = New-Object IO.BinaryWriter $out
    $bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$pngs.Count)
    $offset = 6 + 16 * $pngs.Count
    foreach ($p in $pngs) {
        $s = $p[0]; $data = $p[1]
        $dim = if ($s -ge 256) { 0 } else { $s }
        $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
        $bw.Write([uint16]1); $bw.Write([uint16]32)
        $bw.Write([uint32]$data.Length); $bw.Write([uint32]$offset)
        $offset += $data.Length
    }
    foreach ($p in $pngs) { $bw.Write([byte[]]$p[1]) }
    $bw.Flush()
    [IO.File]::WriteAllBytes($path, $out.ToArray())
}

if (-not (Test-Path $ico)) { New-LinkScopeIcon $ico; "Created icon $ico" }

# ------------------------------------------------------------------ pythonw
$py = (& python -c "import sys; print(sys.executable)").Trim()
$pythonw = Join-Path (Split-Path $py) 'pythonw.exe'
if (-not (Test-Path $pythonw)) { throw "pythonw.exe not found next to $py" }

# ------------------------------------------------------------------ shortcut with AppUserModelID
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class LsShortcut {
    [ComImport, Guid("00021401-0000-0000-C000-000000000046")] class CShellLink {}
    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("000214F9-0000-0000-C000-000000000046")]
    interface IShellLinkW {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder f, int c, IntPtr fd, uint fl);
        void GetIDList(out IntPtr p); void SetIDList(IntPtr p);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder s, int c);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string s);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder s, int c);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string s);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder s, int c);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string s);
        void GetHotkey(out short h); void SetHotkey(short h);
        void GetShowCmd(out int i); void SetShowCmd(int i);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder s, int c, out int i);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string s, int i);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string s, uint r);
        void Resolve(IntPtr h, uint f);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string s);
    }
    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("0000010b-0000-0000-C000-000000000046")]
    interface IPersistFile {
        void GetClassID(out Guid g); [PreserveSig] int IsDirty();
        void Load([MarshalAs(UnmanagedType.LPWStr)] string f, uint m);
        void Save([MarshalAs(UnmanagedType.LPWStr)] string f, bool remember);
        void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string f);
        void GetCurFile([MarshalAs(UnmanagedType.LPWStr)] out string f);
    }
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct PropertyKey { public Guid fmtid; public uint pid; }
    [StructLayout(LayoutKind.Sequential)]
    public struct PropVariant { public ushort vt; public ushort r1, r2, r3; public IntPtr p; public IntPtr p2; }
    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99")]
    interface IPropertyStore {
        void GetCount(out uint c);
        void GetAt(uint i, out PropertyKey k);
        void GetValue(ref PropertyKey k, out PropVariant v);
        void SetValue(ref PropertyKey k, ref PropVariant v);
        void Commit();
    }
    public static void Create(string lnk, string target, string args, string workdir,
                              string icon, string desc, string appId) {
        var link = (IShellLinkW)new CShellLink();
        link.SetPath(target);
        link.SetArguments(args);
        link.SetWorkingDirectory(workdir);
        link.SetIconLocation(icon, 0);
        link.SetDescription(desc);
        var store = (IPropertyStore)link;
        var key = new PropertyKey { fmtid = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3"), pid = 5 };
        var pv = new PropVariant { vt = 31, p = Marshal.StringToCoTaskMemUni(appId) };
        store.SetValue(ref key, ref pv);
        store.Commit();
        Marshal.FreeCoTaskMem(pv.p);
        ((IPersistFile)link).Save(lnk, true);
    }
}
"@

$targets = @(
    (Join-Path ([Environment]::GetFolderPath('Desktop')) 'LinkScope.lnk'),
    (Join-Path ([Environment]::GetFolderPath('Programs')) 'LinkScope.lnk')
)
foreach ($lnk in $targets) {
    [LsShortcut]::Create($lnk, $pythonw, "`"$app`"", $here, $ico,
        'See what is on each Ethernet cable and why ping fails', $AppId)
    "Created $lnk"
}
"Done. Right-click the Desktop icon -> Pin to taskbar."
