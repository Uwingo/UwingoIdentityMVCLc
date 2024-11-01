/**
 * Theme: Dastone - Responsive Bootstrap 5 Admin Dashboard
 * Author: Uwingo
 * Clipboard Js
 */


var clipboard = new ClipboardJS('.btn');

clipboard.on('success', function(e) {
    console.log(e);
});

clipboard.on('error', function(e) {
    console.log(e);
});