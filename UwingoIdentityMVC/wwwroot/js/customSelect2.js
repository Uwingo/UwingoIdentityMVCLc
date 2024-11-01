$(document).ready(function () {
    $('.select2').select2({
        placeholder: function () {
            return $(this).data('placeholder');
        },
        allowClear: true
    });
});
