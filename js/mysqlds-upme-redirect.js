
jQuery(document).ready(function($) {
	
	//	Hides the 'fill your profile' error message.
	$('input[type="submit"]').click(function() {
		$('#mysqlds-edit-form-err-holder').hide()	
	});
	
});
