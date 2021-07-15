
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/pm.h>
#include <linux/i2c.h>
#include <linux/gpio.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#include "apple-auth-coproc.h"

#define SIGNATURE_DATA_LEN_MAX       128
#define CHALLENGE_DATA_LEN_MAX       20
#define ACCESSORY_CERT_DATA_LEN_MAX  1920
#define ACCESSORY_CERT_PAGE_LEN_MAX  128
#define ACCESSORY_CERT_PAGE_NUM_MAX  15
#define IPOD_CERT_DATA_LEN_MAX       1024
#define IPOD_CERT_PAGE_LEN_MAX       128
#define IPOD_CERT_PAGE_NUM_MAX       8

enum act{
    Read = 0,
    Write
};

static struct cp_data {
    struct i2c_client *client;
    struct mutex cp_mutex;

    u8  model;
    u8  dev_version;
    u8  fm_version;
    u8  protocol_major_ver;
    u8  protocol_minor_ver;
    u32 dev_id;
    u8  err;

    u8  auth_ctrl_status;

    u16 sign_data_len;
    u8  sign_data[SIGNATURE_DATA_LEN_MAX];

    u16 challenge_data_len;
    u8  challenge_data[CHALLENGE_DATA_LEN_MAX];

    u16 accessory_cert_data_len;
    u8  accessory_cert_data[ACCESSORY_CERT_PAGE_NUM_MAX][ACCESSORY_CERT_PAGE_LEN_MAX];

    u8 self_test_ctrl_status;

    u16 ipod_cert_data_len;
    u8  ipod_cert_data[IPOD_CERT_DATA_LEN_MAX];

} *_cp;

static int cp_read_write_auth_ctrl_status_reg(struct cp_data *cp, u8 rw)
{
    u8 ctrl_status_reg = 0x10;
    u8 i;
    u8 ret;
    u8 val;
    u8 data[2];

    if(rw == Read) {
        for(i = 0; i < 5; i++)
        {
            ret = i2c_master_send(cp->client, &ctrl_status_reg, 1);
            if(ret == 1) {
                msleep(1);
                ret = i2c_master_recv(cp->client, &val, 1);
                if(ret >= 1) {
                    cp->auth_ctrl_status = val;
                    dev_info(&cp->client->dev, "Control/Status register is read");
                    i = 5;
                    return 0;
                } else {
                    goto err;
                }
            } else {
                if(i == 4)goto err;
            }
        }
    } else if(rw == Write) {
        for(i = 0; i < 5; i++)
        {
            data[0] = ctrl_status_reg;
            data[1] = cp->auth_ctrl_status;
            ret = i2c_master_send(cp->client, data, 2);
            if(ret == 2) {
                dev_info(&cp->client->dev, "Control/Status register is Wrriten");
                i = 5;
                return 0;
            } else {
                if(i == 4)goto err;
            }
        }
    } else {
        goto err;
    }

    return 0;
err:
    dev_warn(&cp->client->dev, "function %s returned error!", __FUNCTION__);
    return -1;
}

static int cp_read_write_self_test_ctrl_status_reg(struct cp_data *cp, u8 rw)
{
    u8 st_ctrl_status_reg = 0x40;
    u8 i;
    u8 ret;
    u8 val;
    u8 data[2];

    if(rw == Read) {
        for(i = 0; i < 5; i++)
        {
            ret = i2c_master_send(cp->client, &st_ctrl_status_reg, 1);
            if(ret == 1) {
                msleep(1);
                ret = i2c_master_recv(cp->client, &val, 1);
                if(ret >= 1) {
                    cp->self_test_ctrl_status = val;
                    dev_info(&cp->client->dev, "Self-test Control/Status register is read");
                    i = 5;
                    return 0;
                } else {
                    goto err;
                }
            } else {
                if(i == 4) goto err;
            }
        }
    } else if(rw == Write) {
        for(i = 0; i < 5; i++)
        {
            data[0] = st_ctrl_status_reg;
            data[1] = cp->self_test_ctrl_status;
            ret = i2c_master_send(cp->client, data, 2);
            if(ret == 2) {
                dev_info(&cp->client->dev, "Self-test Control/Status register is Written");
                i = 5;
                return 0;
            } else {
                if(i == 4) goto err;
            }
        }
    } else {
        goto err;
    }

    return 0;
err:
    dev_warn(&cp->client->dev, "function %s returned error!", __FUNCTION__);
    return -1;
}


static int cp_read_write_signature_data(struct cp_data *cp, u8 rw)
{
    u8 sig_len_reg = 0x11;
    u8 sig_data_reg = 0x12;
    u8 sig_data[SIGNATURE_DATA_LEN_MAX + 1];
    u8 val[3];
    u8 ret;
    u8 i;

    if(rw == Read) {
        //read signature data len
        //retrying for ack
        for(i = 0; i < 5; i++)
        {
            ret = i2c_master_send(cp->client, &sig_len_reg, 1);
            if(ret == 1) {
                msleep(1);
                ret = i2c_master_recv(cp->client, val, 2);
                if(ret == 2) {
                    dev_info(&cp->client->dev, "Signature data length is read");
                    cp->sign_data_len = (val[0] << 8) | val[1] ;
                    i = 5;
                } else {
                    goto err;
                }
            } else {
                if(i == 4) goto err;
            }
        }
        //read signature data
        //retrying for ack
        for(i = 0; i < 5; i++)
        {
            ret = i2c_master_send(cp->client, &sig_data_reg, 1);
            if(ret == 1) {
                msleep(1);
                ret = i2c_master_recv(cp->client, sig_data,  cp->sign_data_len);
                if(ret == cp->sign_data_len) {
                    dev_info(&cp->client->dev, "Signature data is read");
                    memcpy(&cp->sign_data, sig_data, cp->sign_data_len) ;
                    i = 5;
                } else {
                    goto err;
                }
            } else {
                if(i == 4) goto err;
            }
        }
    } else if(rw == Write) {
        for(i = 0; i < 5; i++)
        {
            val[0] = sig_len_reg;
            val[1] = (u8)(cp->sign_data_len >> 8);
            val[2] = (u8)(cp->sign_data_len);
            ret = i2c_master_send(cp->client, val, 3);
            if(ret == 3) {
                dev_info(&cp->client->dev, "Signature data length is Written");
                i = 5;
            } else {
                if(i == 4) goto err;
            }
        }
        for(i = 0; i < 5; i++)
        {
            sig_data[0] = sig_data_reg;
            memcpy(&sig_data[1], &cp->sign_data, cp->sign_data_len);
            ret = i2c_master_send(cp->client, sig_data, cp->sign_data_len + 1);
            if(ret == cp->sign_data_len + 1) {
                dev_info(&cp->client->dev, "Signature data is Written");
                i = 5;
                return 0;
            } else {
                if(i == 4) goto err;
            }
        }
    } else {
        goto err;
    }
    return 0;
err:
    dev_warn(&cp->client->dev, "function %s returned error!", __FUNCTION__);
    return -1;
}

static int cp_read_write_challenge_data(struct cp_data *cp, u8 rw)
{
    u8 challenge_len_reg = 0x20;
    u8 challenge_data_reg = 0x21;
    u8 challenge_data[CHALLENGE_DATA_LEN_MAX + 1];
    u8 val[3];
    u8 ret;
    u8 i;

    if(rw == Read) {
        //read challenge data len
        //retrying for ack
        for(i = 0; i < 5; i++)
        {
            ret = i2c_master_send(cp->client, &challenge_len_reg, 1);
            if(ret == 1) {
                msleep(1);
                ret = i2c_master_recv(cp->client, val, 2);
                if(ret == 2) {
                    cp->challenge_data_len = (val[0] << 8) | val[1] ;
                    dev_info(&cp->client->dev, "Challenge code length is read");
                    i = 5;
                } else {
                    goto err;
                }
            } else {
                if(i == 4) goto err;
            }
        }
        //read challenge data
        //retrying for ack
        for(i = 0; i < 5; i++)
        {
            ret = i2c_master_send(cp->client, &challenge_data_reg, 1);
            if(ret == 1) {
                msleep(1);
                ret = i2c_master_recv(cp->client, challenge_data,  cp->challenge_data_len);
                if(ret == cp->sign_data_len) {
                    memcpy(&cp->challenge_data, challenge_data, cp->challenge_data_len) ;
                    dev_info(&cp->client->dev, "Challenge code is read");
                    i = 5;
                } else {
                    goto err;
                }
            } else {
                if(i == 4) goto err;
            }
        }
    } else if(rw == Write) {
        for(i = 0; i < 5; i++)
        {
            val[0] = challenge_len_reg;
            val[1] = (u8)(cp->challenge_data_len >> 8);
            val[2] = (u8)(cp->challenge_data_len);
            ret = i2c_master_send(cp->client, val, 3);
            if(ret == 3) {
                dev_info(&cp->client->dev, "Challenge data length is written");
                i = 5;
            } else {
                if(i == 4) goto err;
            }
        }
        for(i = 0; i < 5; i++)
        {
            challenge_data[0] = challenge_data_reg;
            memcpy(&challenge_data[1], &cp->challenge_data, cp->challenge_data_len);
            ret = i2c_master_send(cp->client, challenge_data, cp->challenge_data_len + 1);
            if(ret == cp->challenge_data_len + 1) {
                dev_info(&cp->client->dev, "Challenge data is written");
                i = 5;
                return 0;
            } else {
                if(i == 4) goto err;
            }
        }
    } else {
        goto err;
    }
    return 0;
err:
    dev_warn(&cp->client->dev, "function %s returned error!", __FUNCTION__);
    return -1;
}

static int cp_read_accessory_cert_data(struct cp_data *cp)
{
    u8 cert_len_reg = 0x30;
    u8 cert_data_reg = 0x31;
    u8 val[2];
    u8 num, tmp;
    u8 rem;
    u8 ret;
    u8 i;

    //read certificate data len
    //retrying for ack
    for(i = 0; i < 5; i++)
    {
        ret = i2c_master_send(cp->client, &cert_len_reg, 1);
        if(ret == 1) {
            msleep(1);
            ret = i2c_master_recv(cp->client, val, 2);
            if(ret == 2) {
                cp->accessory_cert_data_len = (val[0] << 8) | val[1] ;
                dev_info(&cp->client->dev, "Accessory certificate data length is read");
                i = 5;
            } else {
                goto err;
            }
        } else {
            if(i == 4)
                goto err;
        }
    }

    num = cp->accessory_cert_data_len / ACCESSORY_CERT_PAGE_LEN_MAX;
    rem = cp->accessory_cert_data_len % ACCESSORY_CERT_PAGE_LEN_MAX;
    tmp = num;
    //read challenge data
    //retrying for ack
    for(i = 0; i < 5; i++)
    {
        ret = i2c_master_send(cp->client, &cert_data_reg, 1);
        if(ret == 1) {
            msleep(1);
            do {
                ret = i2c_master_recv(cp->client, &cp->accessory_cert_data[tmp - num][0], ACCESSORY_CERT_PAGE_LEN_MAX);
                if(ret == ACCESSORY_CERT_PAGE_LEN_MAX) {
                    i = 5;
                } else {
                    goto err;
                }
            } while(--num > 0);
            ret = i2c_master_recv(cp->client, &cp->accessory_cert_data[tmp][0], rem);
            dev_info(&cp->client->dev, "Accessory certificate data is read");
        } else {
            if(i == 4)
                goto err;
        }
    }
    return 0;
err:
    dev_warn(&cp->client->dev, "function %s returned error!", __FUNCTION__);
    return -1;
}

static int cp_read_write_ipod_cert_data(struct cp_data *cp, u8 rw)
{
    u8 ipod_cert_len_reg = 0x50;
    u8 ipod_cert_data_reg = 0x51;
    u8 ipod_cert_data[IPOD_CERT_DATA_LEN_MAX + 1];
    u8 val[3];
    u8 ret;
    u8 i;

    if(rw == Read) {
        //read challenge data len
        //retrying for ack
        for(i = 0; i < 5; i++)
        {
            ret = i2c_master_send(cp->client, &ipod_cert_len_reg, 1);
            if(ret == 1) {
                msleep(1);
                ret = i2c_master_recv(cp->client, val, 2);
                if(ret == 2) {
                    cp->ipod_cert_data_len = (val[0] << 8) | val[1] ;
                    dev_info(&cp->client->dev, "iPod Certificate length is read");
                    i = 5;
                } else {
                    goto err;
                }
            } else {
                if(i == 4)
                    goto err;
            }
        }
        //read challenge data
        //retrying for ack
        for(i = 0; i < 5; i++)
        {
            ret = i2c_master_send(cp->client, &ipod_cert_data_reg, 1);
            if(ret == 1) {
                msleep(1);
                ret = i2c_master_recv(cp->client, ipod_cert_data,  cp->ipod_cert_data_len);
                if(ret == cp->ipod_cert_data_len) {
                    memcpy(&cp->ipod_cert_data, ipod_cert_data, cp->ipod_cert_data_len) ;
                    dev_info(&cp->client->dev, "iPod certificate data is read");
                    i = 5;
                } else {
                    goto err;
                }
            } else {
                if(i == 4)
                    goto err;
            }
        }
    } else if(rw == Write) {
        for(i = 0; i < 5; i++)
        {
            val[0] = ipod_cert_len_reg;
            val[1] = (u8)(cp->ipod_cert_data_len >> 8);
            val[2] = (u8)(cp->ipod_cert_data_len);
            ret = i2c_master_send(cp->client, val, 3);
            if(ret == 3) {
                dev_info(&cp->client->dev, "ipod certificate data length is written");
                i = 5;
            } else {
                if(i == 4) goto err;
            }
        }
        for(i = 0; i < 5; i++)
        {
            ipod_cert_data[0] = ipod_cert_data_reg;
            memcpy(&ipod_cert_data[1], &cp->ipod_cert_data, cp->ipod_cert_data_len);
            ret = i2c_master_send(cp->client, ipod_cert_data, cp->ipod_cert_data_len + 1);
            if(ret == cp->ipod_cert_data_len + 1) {
                dev_info(&cp->client->dev, "ipod certificate data is written");
                i = 5;
                return 0;
            } else {
                if(i == 4) goto err;
            }
        }
    } else {
        goto err;
    }
    return 0;
err:
    dev_warn(&cp->client->dev, "function %s returned error!", __FUNCTION__);
    return -1;
}

static int cp_read_info(struct cp_data *cp, u8 *info)
{
    int ret;
    u8 dev_info_reg[10];
    u8 i;

    dev_info_reg[0] = 0;

    //retry to get ack
    for(i = 0; i < 5; i++)
    {
        ret = i2c_master_send(cp->client, dev_info_reg, 1);
        if(ret == 1) {
            msleep(1);
            ret = i2c_master_recv(cp->client, &dev_info_reg[1], 9);
            if(ret == 9) {
                cp->dev_version = dev_info_reg[1];
                cp->fm_version = dev_info_reg[2];
                cp->protocol_major_ver = dev_info_reg[3];
                cp->protocol_minor_ver = dev_info_reg[4];
                cp->dev_id = (dev_info_reg[5] << 24) |
                             (dev_info_reg[6] << 16) |
                             (dev_info_reg[7] <<  8) |
                             (dev_info_reg[8] );
                cp->err = dev_info_reg[9];
                i = 5;
                ret = 0;
            } else {
                return -1;
            }
        }
        if(i == 4) goto err;
    }
    memcpy(info, &dev_info_reg[1], 8);
    return 0;
err:
    dev_warn(&cp->client->dev, "function %s returned error!", __FUNCTION__);
    return -1;
}

static ssize_t write_ctrl(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    u8 ret;

    if(count =! 1)
        goto err_bad_value;

    _cp->auth_ctrl_status = *buf;

    mutex_lock(&_cp->cp_mutex);
    ret = cp_read_write_auth_ctrl_status_reg(_cp, Write);
    mutex_unlock(&_cp->cp_mutex);

    if(ret)
        goto err;

    return sizeof(_cp->auth_ctrl_status);

err:
    return -EIO;

err_bad_value:
    return -EPERM;
}

static ssize_t read_ctrl(struct device *dev, struct device_attribute *attr, char *buf)
{
    u8 ret;

    mutex_lock(&_cp->cp_mutex);
    ret = cp_read_write_auth_ctrl_status_reg(_cp, Read);
    mutex_unlock(&_cp->cp_mutex);

    if(ret)
        goto err;

    *buf = _cp->auth_ctrl_status;

    return sizeof(_cp->auth_ctrl_status);
err:
    return -EIO;
}

static DEVICE_ATTR(cp_ctrl, S_IWUSR | S_IRUGO, read_ctrl, write_ctrl);

static ssize_t write_signature(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    u8 ret;

    if(count > 1026 || count < 2)
        goto err_bad_value;

    _cp->sign_data_len = (((u16)*buf << 8) | (u16)*(buf + 1));

    buf += 2;

    memcpy(&_cp->sign_data, buf, count - 2);

    mutex_lock(&_cp->cp_mutex);
    ret = cp_read_write_signature_data(_cp, Write);
    mutex_unlock(&_cp->cp_mutex);

    if(ret)
        goto err;

    return _cp->sign_data_len + 2;
err:
    return -EIO;

err_bad_value:
    return -EPERM;
}

static ssize_t read_signature(struct device *dev, struct device_attribute *attr, char *buf)
{
    u8 ret;

    mutex_lock(&_cp->cp_mutex);
    ret = cp_read_write_signature_data(_cp, Read);
    mutex_unlock(&_cp->cp_mutex);

    if(ret)
        goto err;

    //first 2 bytes are length and the rest is data
    memcpy(buf, &_cp->sign_data_len, 2);
    buf += 2;
    memcpy(buf, &_cp->sign_data[0], _cp->sign_data_len);

    return _cp->sign_data_len + 2;
err:
    return -EIO;
}

static DEVICE_ATTR(cp_signature, S_IWUSR | S_IRUGO, read_signature, write_signature);

static ssize_t write_challenge(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    u8 ret;

    if(count > 22 || count < 2)
        goto err_bad_value;

    _cp->challenge_data_len = (((u16)*buf << 8) | (u16)*(buf + 1));

    buf += 2;

    memcpy(&_cp->challenge_data, buf, count - 2);

    mutex_lock(&_cp->cp_mutex);
    ret = cp_read_write_challenge_data(_cp, Write);
    mutex_unlock(&_cp->cp_mutex);

    if(ret)
        goto err;

    return _cp->accessory_cert_data_len + 2;
err:
    return -EIO;

err_bad_value:
    return -EPERM;
}

static ssize_t read_challenge(struct device *dev, struct device_attribute *attr, char *buf)
{
    u8 ret;

    mutex_lock(&_cp->cp_mutex);
    ret = cp_read_write_challenge_data(_cp, Read);
    mutex_unlock(&_cp->cp_mutex);

    if(ret)
        goto err;

    //first 2 bytes are length and the rest is data
    memcpy(buf, &_cp->challenge_data_len, 2);
    buf += 2;
    memcpy(buf, &_cp->challenge_data[0], _cp->challenge_data_len);

    return _cp->challenge_data_len + 2;
err:
    return -EIO;
}

static DEVICE_ATTR(cp_challenge, S_IWUSR | S_IRUGO, read_challenge, write_challenge);

static ssize_t read_cert(struct device *dev, struct device_attribute *attr, char *buf)
{
    u8 ret;
    u8 num;
    u8 rem;
    u8 tmp;

    mutex_lock(&_cp->cp_mutex);
    ret = cp_read_accessory_cert_data(_cp);
    mutex_unlock(&_cp->cp_mutex);

    if(ret)
        goto err;

    num = _cp->accessory_cert_data_len / ACCESSORY_CERT_PAGE_LEN_MAX;
    rem = _cp->accessory_cert_data_len % ACCESSORY_CERT_PAGE_LEN_MAX;
    tmp = num;

    //first 2 bytes are length and the rest is data
    memcpy(buf, &_cp->accessory_cert_data_len, 2);
    buf += 2;
    do {
        memcpy(buf, &_cp->accessory_cert_data[tmp - num][0], ACCESSORY_CERT_PAGE_LEN_MAX);
        buf += ACCESSORY_CERT_PAGE_LEN_MAX;
    } while(--num > 0);
    memcpy(buf, &_cp->accessory_cert_data[tmp][0], rem);

    return _cp->accessory_cert_data_len + 2;
err:
    return -EIO;
}

static DEVICE_ATTR(cp_cert, 0444, read_cert, NULL);

static ssize_t show_info(struct device *dev, struct device_attribute *attr, char *buf)
{
    u8 data[9];
    u8 ret;

    mutex_lock(&_cp->cp_mutex);
    ret = cp_read_info(_cp, data);
    mutex_unlock(&_cp->cp_mutex);

    if(ret)
        goto err;

    memcpy(buf,data,sizeof(data));

	return sizeof(data);
err:
    return -EIO;
}

static DEVICE_ATTR(cp_info, 0444, show_info, NULL);

static struct attribute *cp_attributes[] = {
	&dev_attr_cp_info.attr,
	&dev_attr_cp_cert.attr,
	&dev_attr_cp_challenge.attr,
	&dev_attr_cp_signature.attr,
	&dev_attr_cp_ctrl.attr,
	NULL
};

static const struct attribute_group cp_attr_group = {
	.attrs = cp_attributes,
};

//static struct file_operations fops = {
//  .read = NULL,
//  .write = NULL,
//  .open = NULL,
//  .release = NULL
//};


static int cp_probe(struct i2c_client *client,
                    const struct i2c_device_id *id)
{
    int ret = 0;
    u8 data[9];

    /* Check if the adapter supports the needed features */
	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(&client->dev, "i2c_check_functionality error\n");
		return -ENXIO;
	}


    _cp = devm_kzalloc(&client->dev, sizeof(*_cp), GFP_KERNEL);
    if(_cp == NULL)
        return -ENOMEM;


    _cp->client = client;

    cp_read_info(_cp, data);
//  cp_read_accessory_cert_data(_cp);


//    ret = register_chrdev(0, "test-cp", &fops);
//    if (ret < 0) {
//        printk ("Registering the character device failed with %d\n", ret);
//        return ret;
//    }

    ret = sysfs_create_group(&_cp->client->dev.kobj, &cp_attr_group);

    return ret;
}

static int cp_remove(struct i2c_client *client)
{
    return 0;
}

static const struct of_device_id mfi_of_match[] = {
	{ .compatible = "apple,auth-coprocessor", },
	{},
};
MODULE_DEVICE_TABLE(of, mfi_of_match);

/* i2c control layer */
static struct i2c_driver mfi_i2c_driver = {
	.driver = {
		.name = "auth-coproc",
		.of_match_table = of_match_ptr(mfi_of_match),
	},
	.probe	= cp_probe,
	.remove = cp_remove,
};
module_i2c_driver(mfi_i2c_driver);

MODULE_DESCRIPTION("Apple authentication coprocessor driver");
MODULE_AUTHOR("Vahid Gharaee");
MODULE_LICENSE("GPL");
