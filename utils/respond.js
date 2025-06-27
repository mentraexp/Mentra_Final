exports.success = (res, message, data = {}) => {
    return res.status(200).json({ success: true, message, data });
  };
  
  exports.fail = (res, message, code = 'BAD_REQUEST', status = 400) => {
    return res.status(status).json({ success: false, message, code });
  };
  
  exports.validationFail = (res, errors) => {
    return res.status(422).json({ success: false, message: 'Validation failed.', errors });
  };
  