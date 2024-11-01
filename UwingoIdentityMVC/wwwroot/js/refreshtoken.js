setInterval(function () {
    refreshToken();
}, 300000); // 5 dakika

function refreshToken() {
    $.ajax({
        url: '/Home/RefreshTokenApi', 
        type: 'POST',
        success: function (response) {
            if (response === true) {
                console.log('Token yenilendi');
            } else {
                console.log('Token yenileme işlemi başarısız');
            }
        },
        error: function () {
            console.log('Token yenileme işlemi sırasında bir hata oluştu.');
        }
    });
}
