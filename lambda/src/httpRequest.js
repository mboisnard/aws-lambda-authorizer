import got from 'got';

const get = async (url, options) => {
    return got.get(url, options);
};

export default get;
