export const generateOTP = (): string => {
    const limit = 6;
    let OTP = "";

    for (let i = 0; i < limit; i++) {
        OTP += Math.floor(Math.random() * 10)
    }

    return OTP;
}